import hashlib

metrics_transforms = {}


def transform_hash(data, scheme=None):
        scheme = scheme or {"hash": "default"}
        hash_object = hashlib.sha224(str(data) + scheme.get('hash'))
        hex_dig = hash_object.hexdigest()
        return hex_dig


metrics_transforms['sha256'] = transform_hash
metrics_transforms['hash'] = transform_hash


def metrics_transform(type, value, scheme=None):
        if isinstance(value, list):
            for idx, val in enumerate(value):
                value[idx] = metrics_transform(type, val, scheme)
        elif isinstance(value, dict):
            for idx, val in value.iteritems():
                value[idx] = metrics_transform(type, val, scheme)
        else:
            value = metrics_transforms[type](value)
        return value


def transform_object(data, fields):
        def nested_set(dic, path, value):
            keys = path.split(".")
            for key in keys[:-1]:
                dic = dic.setdefault(key, {})
            dic[keys[-1]] = value

        def nested_get(dic, path):
            keys = path.split(".")
            for key in keys[:-1]:
                dic = dic.setdefault(key, {})
            return dic[keys[-1]]

        for field in fields:
            field['path'] = field.get('path') or field.get('name')
            field['search_path'] = field.get('search_path') or field['path']
            field['set_path'] = field.get('set_path') or field['path']
            if data.get(field['search_path']) is not None:
                value = nested_get(data, field['search_path'])
                if field.get('transform'):
                    value = metrics_transform(field['transform'], value)

                nested_set(data, field['set_path'], value)

        return data
