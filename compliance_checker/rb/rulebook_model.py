from __future__ import annotations

import enum
import typing

import pydantic


class RuleListLogic(enum.Enum):
    ALL = "all"
    EXACTLY_ONE = "exactly one"
    AT_LEAST_ONE = "at least one"
    NONE = "none"


class ByteOrder(enum.Enum):
    NATIVE = "="
    LITTLE_ENDIAN = "<"
    BIG_ENDIAN = ">"


class CompressionType(enum.Enum):
    UNSPECIFIED = "UNSPECIFIED"
    NONE = None
    ZLIB = "zlib"
    SZIP = "szip"
    ZSTD = "zstd"
    BZIP2 = "bzip2"
    BLOSC = "blosc"


class Axis(enum.Enum):
    T = "T"
    Z = "Z"
    Y = "Y"
    X = "X"


class LookupTable(pydantic.BaseModel):
    named_axes: list[Axis] = pydantic.Field(default_factory=list)
    filename_drs_elements: str = ""


class Lookup(pydantic.BaseModel):
    lookup: str


class RuleBaseModel(pydantic.BaseModel):
    description: str = ""


class FileFormatRule(RuleBaseModel):
    data_model: str


class DimensionRule(RuleBaseModel):
    dimension: str | Lookup | list[str | Lookup]
    required: bool = True
    size: int = 0


class AttributeRule(RuleBaseModel):
    attribute: str | Lookup | list[str | Lookup]
    required: bool = True
    must_equal: str | float | Lookup | None = None
    allowed_values: list[str | float | Lookup] | None = None
    pattern: str | None = None

    @pydantic.model_validator(mode="before")
    @classmethod
    def check_mutually_exclusive_conditions(cls, data: typing.Any) -> typing.Any:
        if isinstance(data, dict):
            mutually_exclusive_conditions = {"must_equal", "allowed_values", "pattern"}
            if len(mutually_exclusive_conditions.intersection(data.keys())) > 1:
                raise AssertionError("Specified conditions are mutually exclusive.")
        return data


class VariableRule(RuleBaseModel):
    variable: str | Lookup | list[str | Lookup]
    required: bool = True
    dimensions: list[str | Lookup] | None = None
    compression_type: CompressionType = CompressionType.UNSPECIFIED
    compression_level: int | None = None
    rules: RuleUnion | RuleUnionList = pydantic.Field(default_factory=list)


class DataRule(RuleBaseModel):
    dtype: str
    byteorder: ByteOrder = ByteOrder.NATIVE


class ConditionalRule(RuleBaseModel):
    condition: RuleUnion | RuleUnionList = pydantic.Field(..., alias="if")
    dependent: RuleUnion | RuleUnionList = pydantic.Field(..., alias="then")


class RuleListLogicRule(RuleBaseModel):
    logic: RuleListLogic = RuleListLogic.ALL
    rules: RuleUnion | RuleUnionList


class RuleSection(pydantic.BaseModel):
    section: str = pydantic.Field(pattern=r"^[0-9]+(\.[0-9]+)*$")
    heading: str
    rules: RuleUnion | RuleUnionList


class Specification(pydantic.BaseModel):
    url: pydantic.HttpUrl
    name: str
    version: str = pydantic.Field(pattern=r"^[0-9]+(\.[0-9]+)+$")


class RuleBookModel(pydantic.BaseModel):
    version: str = pydantic.Field(pattern=r"^([0-9]+)$")
    specification: Specification
    lookup_table: LookupTable
    rule_sections: list[RuleSection]


RuleUnion = FileFormatRule | DimensionRule | AttributeRule | VariableRule | DataRule | ConditionalRule | RuleListLogicRule
RuleUnionList = list[RuleUnion]
