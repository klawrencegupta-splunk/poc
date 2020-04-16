"""
"""
from models import SOLNAppObjModel
def to_dict(models,connector=None):
    ret={}
    for model in models:
        if isinstance(model,SOLNAppObjModel):
            key=(model.namespace,model.name)
            if connector:
                key=connector.join(key)
            ret[key]=model
    return ret