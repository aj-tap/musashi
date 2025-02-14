from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionValueExpression,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import (
    SigmaCompareExpression,
    SigmaString,
    SpecialChars,
    SigmaCIDRExpression,
)

import re
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any


class superDBBackend(TextQueryBackend):
    """SuperDB backend."""
    name: ClassVar[str] = "SuperDB backend"
    formats: Dict[str, str] = {"default": "SuperDB queries"}
    requires_pipeline: bool = False

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT, ConditionAND, ConditionOR
    )
    parenthesize: bool = True
    group_expression: ClassVar[str] = "({expr})"
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "=="
    field_quote: ClassVar[str] = "`"
    field_quote_pattern: ClassVar[Pattern] = re.compile("^[a-zA-Z0-9_]*$")
    field_quote_pattern_negation: ClassVar[bool] = True
    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "%"
    wildcard_single: ClassVar[str] = "_"
    wildcard_glob: ClassVar[str] = "*"
    wildcard_glob_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = "\\"
    bool_values: ClassVar[Dict[bool, str]] = {True: "true", False: "false"}
    
    startswith_expression: ClassVar[str] = "grep(/^{value}.*/, this['{field}'])"
    endswith_expression: ClassVar[str] = "grep(/.*{value}/, this['{field}'])"
    contains_expression: ClassVar[str] = "grep(/.*{value}.*/, this['{field}'])"
    wildcard_match_expression: ClassVar[str] = "grep(/.*{value}.*/, this['{field}'])"
    
    field_exists_expression: ClassVar[str] = "{field} == {field}"
    wildcard_match_str_expression: ClassVar[str] = "grep(/.*{value}.*/, {field})"
    re_expression: ClassVar[str] = "{field} REGEXP '{regex}'"
    re_escape_char: ClassVar[str] = ""
    re_escape: ClassVar[Tuple[str]] = ()
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = True
    case_sensitive_match_expression: ClassVar[str] = "{field} GLOB {value} ESCAPE '\\'"
    
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }
    
    field_equals_field_expression: ClassVar[Optional[str]] = None
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)
    field_null_expression: ClassVar[str] = "{field}==null"
    
    convert_or_as_in: ClassVar[bool] = False
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "IN"
    list_separator: ClassVar[str] = ", "
    
    deferred_start: ClassVar[str] = ""
    deferred_separator: ClassVar[str] = ""
    deferred_only_query: ClassVar[str] = ""

    table = "<TABLE_NAME>"

    def convert_value_str(self, s: SigmaString, state: ConversionState, no_quote: bool = False, glob_wildcards: bool = False) -> str:
        """Convert a SigmaString into a query-compatible string."""
        converted = s.convert(
            escape_char=self.escape_char,
            wildcard_multi=self.wildcard_glob if glob_wildcards else self.wildcard_multi,
            wildcard_single=self.wildcard_glob_single if glob_wildcards else self.wildcard_single,
            add_escaped=self.add_escaped,
            filter_chars=self.filter_chars,
        ).replace("'", "''")

        return self.quote_string(converted) if self.decide_string_quoting(s) and not no_quote else converted

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions."""
        remove_quote = True

        if cond.value.endswith(SpecialChars.WILDCARD_MULTI) and not cond.value[:-1].contains_special():
            expr, value = self.startswith_expression, cond.value[:-1]
        elif cond.value.startswith(SpecialChars.WILDCARD_MULTI) and not cond.value[1:].contains_special():
            expr, value = self.endswith_expression, cond.value[1:]
        elif cond.value.startswith(SpecialChars.WILDCARD_MULTI) and cond.value.endswith(SpecialChars.WILDCARD_MULTI) and not cond.value[1:-1].contains_special():
            expr, value = self.contains_expression, cond.value[1:-1]
        elif any(x in cond.value for x in [self.wildcard_multi, self.wildcard_single, self.escape_char]) or cond.value.contains_special():
            expr, value = self.wildcard_match_expression, cond.value
        else:
            expr, value, remove_quote = "{field}" + self.eq_token + "{value}", cond.value, False

        return expr.format(
            field=self.escape_and_quote_field(cond.field),
            value=self.convert_value_str(value, state, remove_quote)
        )

    def convert_condition_field_eq_val_cidr(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field matches CIDR value expressions."""
        expanded = cond.value.expand()
        expanded_cond = ConditionOR(
            [ConditionFieldEqualsValueExpression(cond.field, SigmaString(network)) for network in expanded],
            cond.source,
        )
        return self.convert_condition(expanded_cond, state)

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        """Finalizes the SuperDB query."""
        return f"{query}"

    def convert_condition_val_str(self, cond: ConditionValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Disallow value-only string expressions."""
        raise SigmaFeatureNotSupportedByBackendError("Value-only string expressions are not supported by the backend.")

    def convert_condition_val_num(self, cond: ConditionValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Disallow value-only number expressions."""
        raise SigmaFeatureNotSupportedByBackendError("Value-only number expressions are not supported by the backend.")
