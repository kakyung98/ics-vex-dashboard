"""Split CPE 2.3 formatted strings without losing quoted attribute characters.

Keeps the original bindings (including escaped wildcards) for source matching.
This structural parser does not claim full WFN name matching validation.
"""
import string

_PLAIN=set(string.ascii_letters+string.digits+'_.-*?')
_QUOTED=set(string.punctuation)


def formatted_parts(value):
    if not isinstance(value,str) or not value.startswith('cpe:2.3:'):
        return []
    fields=[];token=[];i=8
    while i<len(value):
        char=value[i]
        if char=='\\':
            if i+1>=len(value) or value[i+1] not in _QUOTED:return []
            token.extend((char,value[i+1]));i+=2;continue
        if char==':':
            if not token:return []
            fields.append(''.join(token));token=[]
        elif char in _PLAIN:token.append(char)
        else:return []
        i+=1
    if not token:return []
    fields.append(''.join(token))
    if len(fields)!=11 or fields[0] not in {'a','o','h','*','-'}:return []
    return ['cpe','2.3',*fields]
