"""
OpenSOC Forge - Sigma Rule Compiler.
Translates vendor-neutral Sigma detection rules (YAML) into:
1. Elasticsearch Lucene Query / OpenSearch DSL
2. Wazuh XML Rule definitions
3. Suricata NIDS Rule signatures
"""

import re
from typing import Any, Dict, List, Optional
import yaml


class SigmaCompilationError(Exception):
    pass


class SigmaCompiler:
    """
    Compiler engine that converts generic Sigma detection logic into target platform rules.
    """

    def compile(self, sigma_yaml_text: str) -> Dict[str, Any]:
        """
        Parses Sigma YAML rule and outputs compiled representations for Elastic, Wazuh, and Suricata.
        """
        try:
            rule_data = yaml.safe_load(sigma_yaml_text)
        except Exception as e:
            raise SigmaCompilationError(f"Invalid YAML format: {str(e)}")

        if not isinstance(rule_data, dict):
            raise SigmaCompilationError("Sigma rule must be a valid YAML mapping")

        # Required fields validation
        required_fields = ["title", "logsource", "detection"]
        missing = [f for f in required_fields if f not in rule_data]
        if missing:
            raise SigmaCompilationError(f"Missing required Sigma fields: {', '.join(missing)}")

        title = rule_data.get("title", "Untitled Rule")
        rule_id = rule_data.get("id", "SIGMA-GENERIC-001")
        level = rule_data.get("level", "medium").lower()
        logsource = rule_data.get("logsource", {})
        detection = rule_data.get("detection", {})
        condition = detection.get("condition", "selection")

        # Parse selections
        selections = {}
        for k, v in detection.items():
            if k != "condition":
                selections[k] = v

        # 1. Compile to Elasticsearch Query DSL
        es_query = self._compile_to_elasticsearch(logsource, selections, condition)

        # 2. Compile to Wazuh XML Rule
        wazuh_xml = self._compile_to_wazuh(rule_id, title, level, selections)

        # 3. Compile to Suricata Rule (if network-relevant)
        suricata_sig = self._compile_to_suricata(rule_id, title, selections, logsource)

        return {
            "title": title,
            "rule_id": rule_id,
            "level": level,
            "condition": condition,
            "targets": {
                "elasticsearch": {
                    "query_dsl": es_query,
                    "lucene_string": self._format_lucene_string(selections),
                },
                "wazuh": {
                    "xml_rule": wazuh_xml,
                    "target_group": logsource.get("product", "sysmon"),
                },
                "suricata": {
                    "signature": suricata_sig,
                    "supported": bool(suricata_sig),
                },
            },
        }

    def _compile_to_elasticsearch(self, logsource: Dict[str, Any], selections: Dict[str, Any], condition: str) -> Dict[str, Any]:
        must_clauses: List[Dict[str, Any]] = []

        # Add logsource filter
        if "category" in logsource:
            must_clauses.append({"match": {"event.category": logsource["category"]}})
        if "product" in logsource:
            must_clauses.append({"match": {"agent.type": logsource["product"]}})

        for sel_name, sel_body in selections.items():
            if isinstance(sel_body, dict):
                for field, val in sel_body.items():
                    # Handle modifier like CommandLine|contains
                    if "|contains" in field:
                        raw_field = field.split("|")[0]
                        if isinstance(val, list):
                            should_terms = [{"wildcard": {f"{raw_field}": f"*{v}*"}} for v in val]
                            must_clauses.append({"bool": {"should": should_terms, "minimum_should_match": 1}})
                        else:
                            must_clauses.append({"wildcard": {f"{raw_field}": f"*{val}*"}})
                    elif "|endswith" in field:
                        raw_field = field.split("|")[0]
                        must_clauses.append({"wildcard": {f"{raw_field}": f"*{val}"}})
                    else:
                        if isinstance(val, list):
                            must_clauses.append({"terms": {field: val}})
                        else:
                            must_clauses.append({"match_phrase": {field: val}})
            elif isinstance(sel_body, list):
                # Simple list of keywords
                should_keywords = [{"multi_match": {"query": kw, "type": "phrase"}} for kw in sel_body]
                must_clauses.append({"bool": {"should": should_keywords, "minimum_should_match": 1}})

        return {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            }
        }

    def _compile_to_wazuh(self, rule_id: str, title: str, level: str, selections: Dict[str, Any]) -> str:
        level_map = {"low": 3, "medium": 7, "high": 10, "critical": 14}
        w_level = level_map.get(level, 7)
        numeric_id = re.sub(r"[^\d]", "", rule_id)
        if not numeric_id or len(numeric_id) < 5:
            numeric_id = "199001"
        else:
            numeric_id = numeric_id[:6]

        field_tags = []
        for sel_name, sel_body in selections.items():
            if isinstance(sel_body, dict):
                for field, val in sel_body.items():
                    clean_field = field.split("|")[0]
                    if isinstance(val, list):
                        val_str = "|".join(str(v) for v in val)
                    else:
                        val_str = str(val)
                    field_tags.append(f'    <field name="{clean_field}">{val_str}</field>')

        fields_block = "\n".join(field_tags) if field_tags else "    <match>malicious</match>"

        return f"""<group name="opensoc,sigma,">
  <rule id="{numeric_id}" level="{w_level}">
    <description>{title}</description>
{fields_block}
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
</group>"""

    def _compile_to_suricata(self, rule_id: str, title: str, selections: Dict[str, Any], logsource: Dict[str, Any]) -> Optional[str]:
        numeric_id = re.sub(r"[^\d]", "", rule_id)
        if not numeric_id or len(numeric_id) < 6:
            numeric_id = "202999"
        else:
            numeric_id = numeric_id[:7]

        # Extract contents to match
        contents = []
        for sel_body in selections.values():
            if isinstance(sel_body, dict):
                for k, v in sel_body.items():
                    if isinstance(v, str):
                        contents.append(v)
                    elif isinstance(v, list):
                        contents.extend([str(item) for item in v if isinstance(item, str)])

        if not contents:
            return None

        # Build suricata content options
        content_options = ' '.join([f'content:"{c[:32]}";' for c in contents[:2]])
        clean_title = title.replace('"', '')
        return f'alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"OPENSOC SIGMA {clean_title}"; {content_options} classtype:trojan-activity; sid:{numeric_id}; rev:1;)'

    def _format_lucene_string(self, selections: Dict[str, Any]) -> str:
        clauses = []
        for sel_body in selections.values():
            if isinstance(sel_body, dict):
                for field, val in sel_body.items():
                    clean_field = field.split("|")[0]
                    if isinstance(val, list):
                        val_terms = " OR ".join([f'"{v}"' for v in val])
                        clauses.append(f"{clean_field}:({val_terms})")
                    else:
                        clauses.append(f'{clean_field}:"{val}"')
        return " AND ".join(clauses) if clauses else "*:*"


sigma_compiler = SigmaCompiler()
