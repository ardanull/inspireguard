from __future__ import annotations
import re, yaml
class SigmaLabService:
    def parse_rule(self, rule_yaml: str):
        data = yaml.safe_load(rule_yaml) or {}
        detection = data.get('detection', {})
        return {'title': data.get('title', 'untitled'), 'level': data.get('level', 'medium'), 'selection': detection.get('selection', {}), 'condition': detection.get('condition', 'selection')}
    def simulate(self, rule_yaml: str, events: list[dict]):
        rule = self.parse_rule(rule_yaml)
        matched = []
        for idx, event in enumerate(events):
            ok = True
            for field, expected in (rule['selection'] or {}).items():
                actual = str(event.get(field, ''))
                expected = str(expected)
                if '*' in expected:
                    pattern = '^' + re.escape(expected).replace('\\*', '.*') + '$'
                    if re.match(pattern, actual, flags=re.IGNORECASE) is None:
                        ok = False; break
                elif actual.lower() != expected.lower():
                    ok = False; break
            if ok:
                matched.append({'index': idx, 'event': event})
        return {'title': rule['title'], 'level': rule['level'], 'logic': rule['condition'], 'total_events': len(events), 'matches': matched, 'match_count': len(matched)}
