import logging

from compliance_checker.base import BaseCheck, BaseNCCheck
from compliance_checker.rb import rulebook_imp

logger = logging.getLogger(__name__)


class RuleBookCheck(BaseNCCheck, BaseCheck):
    register_checker = True
    _cc_spec = "rb"
    _cc_spec_version = "1.0"
    _cc_description = "Rulebook (RB)"
    _cc_url = ""
    _cc_display_headers = {3: "Errors", 2: "Warnings", 1: "Info"}

    def __init__(self, options=None):  # initialize with parent methods and data
        super().__init__(options)
        self._rulebook_file = None if options is None or "rulebook" not in options else options["rulebook"]

    def check_rulebook_compliance(self, ds):
        try:
            rulebook = rulebook_imp.RuleBook.from_file(self._rulebook_file)
        except (FileNotFoundError, TypeError):
            raise ValueError("A valid RuleBook file must be given as option to the RuleBook checker.") from None
        return rulebook.validate(ds)
