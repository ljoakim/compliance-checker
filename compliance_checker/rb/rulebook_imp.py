from __future__ import annotations

import pathlib
import re
import typing

import netCDF4
import numpy as np
import yaml

from compliance_checker import cfutil
from compliance_checker.base import BaseCheck, Result, TestCtx
from compliance_checker.rb import rulebook_model


class RuleBook:
    def __init__(self, rule_book: str) -> None:
        self._rule_book = rulebook_model.RuleBookModel.model_validate(rule_book)
        self._lookup_table = {}

    @staticmethod
    def from_file(rule_book_file: pathlib.Path | str) -> RuleBook:
        with open(rule_book_file) as f:
            rule_book_str = yaml.safe_load(f)
            return RuleBook(rule_book_str)

    def validate(self, ds: netCDF4.Dataset) -> list[Result]:
        self._lookup_table, result = self._rebuild_lookup_table(ds)
        results = [result]
        for rule_section in self._rule_book.rule_sections:
            result = self._apply_rule_section(ds, rule_section)
            result.msgs = [self._flatten_result_tree(result)]  # Assign single hierarchical error message
            result.children = None  # Disconnect children
            results.append(result)
        return results

    def _flatten_result_tree(self, result, indent=0) -> str:
        # TODO: This is a temporary solution with some formatting magic.
        #       Formatting should be taken care of outside of the checker.
        indent_string = "\n" + "  " * (indent + 1)
        err = "\u2714 " if result.success() else "\u2716 "
        level_msg = (indent_string if indent > 0 else "") + err + (indent_string + "  ").join(result.msgs)
        if not result.success():
            for child in result.children:
                level_msg = level_msg + self._flatten_result_tree(child, indent + 1)
        return level_msg

    def _rebuild_lookup_table(self, ds: netCDF4.Dataset) -> tuple[dict[str, str], Result]:
        ctx = TestCtx(BaseCheck.HIGH, "Building lookup table")
        lookup_table = {}

        # Axis names.
        # TODO: This needs to be made more robust.
        #       It relies on coordinate variables having the 'axis' attribute,
        #       which formally is not a 'must'.
        axis_variables = cfutil.get_axis_variables(ds)
        axis_method_mapping = {
            "T": cfutil.get_time_variables,
            "Z": cfutil.get_z_variables,
            "Y": cfutil.get_latitude_variables,
            "X": cfutil.get_longitude_variables,
        }
        for axis in self._rule_book.lookup_table.named_axes:
            try:
                lookup_table[axis.value] = set(axis_method_mapping[axis.value](ds)).intersection(axis_variables).pop()
            except Exception:
                ctx.add_failure(f"Failed to get name for '{axis.value}' axis.")

        # DRS elements
        if self._rule_book.lookup_table.filename_drs_elements:
            try:
                lookup_table.update(self._extract_drs_elements(pathlib.Path(ds.filepath()), self._rule_book.lookup_table.filename_drs_elements))
            except Exception as e:
                ctx.add_failure(str(e))

        return lookup_table, ctx.to_result()

    def _lookup(self, key: typing.Any) -> typing.Any:
        if isinstance(key, rulebook_model.Lookup) and key.lookup in self._lookup_table:
            return self._lookup_table[key.lookup]
        else:
            return key

    def _extract_drs_elements(
        self,
        full_path: pathlib.Path,
        filename_drs: str,
    ) -> dict[str, str]:
        def match_regex_pattern(regex, string):
            try:
                elements = re.match(regex, str(string)).groupdict()
            except AttributeError as e:
                raise AttributeError(f"Failed to extract DRS elements from string:" f" '{string}' is incorrectly formatted.") from e
            return elements

        file_regex = filename_drs.replace("[", r"").replace("]", r"").replace("<", r"(?P<").replace(">", r">.+)")
        filename_drs_elements = match_regex_pattern(file_regex, full_path.name)
        return filename_drs_elements

    def _apply_rule_section(
        self,
        ds: netCDF4.Dataset,
        rc: rulebook_model.RuleSection,
    ) -> Result:
        rules_result_list = self._apply_rule_or_rule_list(ds, rc.rules)
        logic_result, logic_message = self._rule_list_logic(rules_result_list, rulebook_model.RuleListLogic.ALL)
        return Result(
            BaseCheck.LOW if logic_result else BaseCheck.HIGH,
            logic_result,
            name=[f"§{rc.section} {rc.heading}"],
            msgs=None if logic_result else [logic_message],
            children=rules_result_list,
        )

    def _apply_rule_or_rule_list(
        self,
        ds: netCDF4.Dataset | netCDF4.Variable,
        rules: rulebook_model.RuleUnionList,
    ) -> list[Result]:
        if not isinstance(rules, list):
            rules = [rules]

        rules_result_list = []
        for rule in rules:
            if isinstance(rule, rulebook_model.FileFormatRule):
                rules_result_list.append(self._apply_format_rule(ds, rule))
            elif isinstance(rule, rulebook_model.DimensionRule):
                rules_result_list.extend(self._expand_and_apply_dimension_rule(ds, rule))
            elif isinstance(rule, rulebook_model.AttributeRule):
                rules_result_list.extend(self._expand_and_apply_attribute_rule(ds, rule))
            elif isinstance(rule, rulebook_model.VariableRule):
                rules_result_list.extend(self._expand_and_apply_variable_rule(ds, rule))
            elif isinstance(rule, rulebook_model.DataRule):
                rules_result_list.append(self._apply_variable_data_rule(ds, rule))
            elif isinstance(rule, rulebook_model.ConditionalRule):
                rules_result_list.append(self._apply_conditional_rule(ds, rule))
            elif isinstance(rule, rulebook_model.RuleListLogicRule):
                rules_result_list.append(self._apply_rule_list_logic_rule(ds, rule))
        return rules_result_list

    def _apply_format_rule(
        self,
        ds: netCDF4.Dataset,
        r: rulebook_model.FileFormatRule,
    ) -> Result:
        ctx = TestCtx(BaseCheck.HIGH, messages=[r.description] if r.description else None)
        ctx.assert_true(ds.data_model == r.data_model, f"Data model is '{ds.data_model}' but must be '{r.data_model}'.")
        result = ctx.to_result()
        if result.success():
            result.msgs.append("Format rule met.")
        return result

    def _expand_and_apply_dimension_rule(
        self,
        ds: netCDF4.Dataset,
        r: rulebook_model.DimensionRule,
    ) -> list[Result]:
        if isinstance(r.dimension, list):
            rules = [r.model_copy(update={"dimension": d}) for d in r.dimension]
        else:
            rules = [r]
        return [self._apply_dimension_rule(ds, rule) for rule in rules]

    def _apply_dimension_rule(
        self,
        ds: netCDF4.Dataset,
        r: rulebook_model.DimensionRule,
    ) -> Result:
        dimension_name = self._lookup(r.dimension)
        ctx = TestCtx(BaseCheck.HIGH, messages=[r.description] if r.description else None)
        try:
            dimension = ds.dimensions[dimension_name]
        except KeyError:
            ctx.assert_true(
                not r.required,
                f"Dimension '{dimension_name}' is required but missing.",
            )
        else:
            ctx.assert_true(
                r.size == 0 or r.size == dimension.size,
                f"Dimension '{dimension_name}' has size {dimension.size} but must" f" be {r.size}.",
            )
        result = ctx.to_result()
        if result.success():
            result.msgs.append(f"Dimension '{dimension_name}' meets specified rules.")
        return result

    def _expand_and_apply_attribute_rule(
        self,
        ds: netCDF4.Dataset | netCDF4.Variable,
        r: rulebook_model.AttributeRule,
    ) -> list[Result]:
        if isinstance(r.attribute, list):
            rules = [r.model_copy(update={"attribute": v}) for v in r.attribute]
        else:
            rules = [r]
        return [self._apply_attribute_rule(ds, rule) for rule in rules]

    def _apply_attribute_rule(
        self,
        ds: netCDF4.Dataset | netCDF4.Variable,
        r: rulebook_model.AttributeRule,
    ) -> Result:
        attribute_name = self._lookup(r.attribute)
        ctx = TestCtx(BaseCheck.HIGH, messages=[r.description] if r.description else None)
        try:
            value = self._lookup(ds.getncattr(attribute_name))
        except AttributeError:
            ctx.assert_true(
                not r.required,
                f"Attribute '{attribute_name}' is required but missing.",
            )
        else:
            if r.must_equal is not None:
                must_equal = self._lookup(r.must_equal)
                ctx.assert_true(
                    self._exactly_equal(value, must_equal),
                    f"Attribute '{attribute_name}' has value '{value}' but must equal" f" '{must_equal}'.",
                )
            elif r.allowed_values is not None:
                allowed_values = [self._lookup(v) for v in r.allowed_values]
                ctx.assert_true(
                    value in allowed_values,
                    f"Attribute '{attribute_name}' has value '{value}' but must be one of" f" {allowed_values}.",
                )
            elif r.pattern is not None:
                pattern = self._lookup(r.pattern)
                ctx.assert_true(
                    re.search(pattern, value),
                    f"Attribute '{attribute_name}' has value '{value}' which" f" does not match the pattern '{pattern}'.",
                )
        result = ctx.to_result()
        if result.success():
            result.msgs.append(f"Attribute '{attribute_name}' meets specified rules.")
        return result

    def _expand_and_apply_variable_rule(
        self,
        ds: netCDF4.Variable,
        r: rulebook_model.VariableRule,
    ) -> list[Result]:
        if isinstance(r.variable, list):
            rules = [r.model_copy(update={"variable": v}) for v in r.variable]
        else:
            rules = [r]
        return [self._apply_variable_rule(ds, rule) for rule in rules]

    def _apply_variable_rule(
        self,
        ds: netCDF4.Variable,
        r: rulebook_model.VariableRule,
    ) -> Result:
        variable_name = self._lookup(r.variable)
        ctx = TestCtx(BaseCheck.HIGH, variable=variable_name, messages=[r.description] if r.description else None)
        rules_result_list = []
        try:
            variable = ds.variables[variable_name]
        except KeyError:
            ctx.assert_true(
                not r.required,
                f"Variable '{variable_name}' is required but missing.",
            )
        else:
            if r.dimensions is not None:
                dimensions = tuple([self._lookup(d) for d in r.dimensions])
                ctx.assert_true(
                    variable.dimensions == dimensions,
                    f"Variable '{variable_name}' has dimensions {variable.dimensions}, must be {dimensions}.",
                )
            filters = variable.filters()
            if r.compression_type != rulebook_model.CompressionType.UNSPECIFIED:
                var_compression_type = rulebook_model.CompressionType.NONE
                for t in rulebook_model.CompressionType:
                    if t not in [rulebook_model.CompressionType.UNSPECIFIED, rulebook_model.CompressionType.NONE] and filters[t.value]:
                        var_compression_type = t.value
                        break
                ctx.assert_true(
                    var_compression_type == r.compression_type.value,
                    f"Variable '{variable_name}' has compression type '{var_compression_type}', must be '{r.compression_type.value}'.",
                )
            if r.compression_level is not None:
                ctx.assert_true(
                    filters["complevel"] == r.compression_level,
                    f"Variable '{variable_name}' has compression level {filters['complevel']}, must be {r.compression_level}.",
                )

            rules = r.rules if isinstance(r.rules, list) else [r.rules]
            if len(rules) > 0:
                rules_result_list = self._apply_rule_or_rule_list(variable, rules)
                logic_result, logic_message = self._rule_list_logic(rules_result_list, rulebook_model.RuleListLogic.ALL)
                ctx.assert_true(logic_result, logic_message)

        result = ctx.to_result()
        result.children = rules_result_list
        if result.success():
            result.msgs.append(f"Variable '{variable_name}' meets specified rules.")
        return result

    def _apply_variable_data_rule(
        self,
        ds: netCDF4.Variable,
        r: rulebook_model.DataRule,
    ) -> Result:
        ctx = TestCtx(BaseCheck.HIGH, messages=[r.description] if r.description else None)
        ctx.assert_true(
            ds.dtype.name == r.dtype,
            f"Data has dtype '{ds.dtype.name}' but must be '{r.dtype}'.",
        )
        ctx.assert_true(
            ds.dtype.byteorder == r.byteorder.value,
            f"Data has byteorder '{ds.dtype.byteorder}' but must be" f" '{r.byteorder.value}' ({r.byteorder}).",
        )
        result = ctx.to_result()
        if result.success():
            result.msgs.append(f"Data of variable '{self._lookup(ds.name)}' meets specified rules.")
        return result

    def _apply_conditional_rule(
        self,
        ds: netCDF4.Dataset | netCDF4.Variable,
        r: rulebook_model.ConditionalRule,
    ) -> Result:
        ctx = TestCtx(BaseCheck.HIGH, messages=[r.description] if r.description else None)
        dependent_result_list = []

        condition_result_list = self._apply_rule_or_rule_list(ds, r.condition)
        logic_result, _ = self._rule_list_logic(condition_result_list, rulebook_model.RuleListLogic.ALL)
        if logic_result:
            dependent_result_list = self._apply_rule_or_rule_list(ds, r.dependent)
            logic_result, logic_message = self._rule_list_logic(dependent_result_list, rulebook_model.RuleListLogic.ALL)
            ctx.assert_true(logic_result, "Checking dependent rules: " + logic_message)

        result = ctx.to_result()
        result.children = dependent_result_list
        if result.success():
            result.msgs.append("Conditional rule met.")
        return result

    def _apply_rule_list_logic_rule(
        self,
        ds: netCDF4.Dataset | netCDF4.Variable,
        r: rulebook_model.RuleListLogicRule,
    ) -> list[Result]:
        ctx = TestCtx(BaseCheck.HIGH, messages=[r.description] if r.description else None)

        rules_result_list = self._apply_rule_or_rule_list(ds, r.rules)
        logic_result, logic_message = self._rule_list_logic(rules_result_list, r.logic)
        ctx.assert_true(logic_result, logic_message)

        result = ctx.to_result()
        result.children = rules_result_list
        return result

    def _rule_list_logic(
        self,
        validation_nodes: list[Result],
        logic: rulebook_model.RuleListLogic,
    ) -> tuple[bool, str]:
        validations_ok = [node.value[0] == node.value[1] for node in validation_nodes]
        score = sum(validations_ok)
        total = len(validations_ok)
        if logic == rulebook_model.RuleListLogic.ALL:
            if not all(validations_ok):
                return (False, f"All rules must be met. Currently {score} out of {total} are met.")
            else:
                return (True, "All rules are met.")

        elif logic == rulebook_model.RuleListLogic.EXACTLY_ONE:
            if sum(validations_ok) != 1:
                return (False, f"Exactly one (one and only one) rule must be met. Currently {score} out of {total} are met.")
            else:
                return (True, "Exactly one rule is met.")

        elif logic == rulebook_model.RuleListLogic.AT_LEAST_ONE:
            if not any(validations_ok) == 0:
                return (False, f"At least one rule must be met. Currently {score} out of {total} are met.")
            else:
                return (True, "At least one rule is met.")

        else:  # if logic == rulebook_model.RuleListLogic.NONE:
            if any(validations_ok):
                return (False, f"No rules must be met. Currently {score} out of {total} are met.")
            else:
                return (True, "No rules are met.")

    def _exactly_equal(self, a: typing.Any, b: typing.Any) -> bool:
        float_types = (float, np.float32, np.float64)
        if isinstance(a, float_types) or isinstance(b, float_types):
            return np.float64(a) == np.float64(b)
        else:
            return a == b
