"""Bounded response grammars shared by the agent and hosted model gateway."""
import re


def _wrap(ids,row):
    ids=list(ids)
    if not 1<=len(ids)<=16 or len(set(ids))!=len(ids) or any(not isinstance(key,str) or not re.fullmatch(r'h\d{1,6}',key) for key in ids):
        raise ValueError('invalid risk response identifiers')
    return {'type':'object','properties':{'results':{'type':'object','properties':{key:row for key in ids},'required':ids,'additionalProperties':False}},'required':['results'],'additionalProperties':False}


def verification(ids):
    common={'reason':{'type':'string','maxLength':180},'vulnerable':{'type':'boolean'},
            'needs_context':{'type':'boolean'},'control_quote':{'type':'string','maxLength':180}}
    variants=[]
    for vulnerable in (True,False):
        fields={**common,'vulnerable':{'const':vulnerable}}
        evidence={'type':'string','minLength':8,'maxLength':180} if vulnerable else {'const':''}
        fields.update(source_quote=evidence,sink_quote=evidence)
        variants.append({'type':'object','properties':fields,'required':list(fields),'additionalProperties':False})
    return _wrap(ids,{'oneOf':variants})


def criticism(ids):
    fields={'verdict':{'type':'string','enum':['exploitable','blocked','uncertain']},
            'control':{'type':'string','enum':['validation','allowlist','parameterised','escaping','authorization','unreachable','static','nonsecurity','none']},
            'quote':{'type':'string','maxLength':180},'why':{'type':'string','maxLength':180}}
    return _wrap(ids,{'type':'object','properties':fields,'required':list(fields),'additionalProperties':False})
