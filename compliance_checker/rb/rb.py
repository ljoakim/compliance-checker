import logging
import pathlib

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
        self._rulebook = rulebook_imp.RuleBook.from_file(pathlib.Path(__file__).parent / "rulebook_example.yml")

    def check_rulebook_compliance(self, ds):
        return self._rulebook.validate(ds)
