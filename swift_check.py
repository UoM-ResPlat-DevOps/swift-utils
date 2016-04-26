import swiftclient
import hashlib
import argparse
import os
import concurrent.futures as cfutures
import threading

SEGMENT_PREFIX = '.file-segments/'


def parse_segment_name(name):
    obj_name = name[len(SEGMENT_PREFIX):]
    idx1 = obj_name.rfind('/')
    seg_idx = int(obj_name[idx1 + 1:])
    obj_name = obj_name[:idx1]
    idx2 = obj_name.rfind('/')
    obj_name = obj_name[:idx2]
    return obj_name, seg_idx


def swift_check(root, auth_url, username, password, tenant_name, container_name, auth_version='2', insecure=False,
                region_name=None, prefix=None, full_listing=True, max_threads=5):
    def check(obj, root, segmented):
        result = {'thread': threading.current_thread().getName(), 'obj_name': obj['name'],
                  'obj_size': obj['bytes'], 'object_hash': obj['hash'], 'segment_info': None,
                  'file_path': None, 'file_type': 'file', 'file_size': 0, 'file_hash': None, 'file_exists': False,
                  'match': False}
        path = root + (container_name if root.endswith('/') else ('/' + container_name)) + '/'
        if obj['name'].startswith(SEGMENT_PREFIX):
            result['segment_info'] = {'object': obj['obj_name'], 'index': obj['seg_idx'], 'offset': obj['seg_offset'],
                                      'length': obj['bytes'], 'total': obj['total_size']}
            path += obj['obj_name']
            result['file_path'] = path
            if os.path.exists(path):
                result['file_exists'] = True
                if os.path.isfile(path):
                    result['file_type'] = 'file'
                    result['file_size'] = os.path.getsize(path)
                else:
                    raise ValueError(path + ' is not a regular file.')
                result['file_hash'] = md5hash(path, result['segment_info']['offset'], result['segment_info']['length'])
                if result['file_hash'] == result['object_hash']:
                    result['match'] = True
        else:
            path += obj['name']
            result['file_path'] = path
            if os.path.exists(path):
                result['file_exists'] = True
                if os.path.isdir(path) and obj['bytes'] == 0:
                    result['file_type'] = 'directory'
                    result['file_size'] = 0
                    result['match'] = True
                elif os.path.isfile(path):
                    result['file_type'] = 'file'
                    result['file_size'] = os.path.getsize(path)
                    if result['obj_size'] == result['file_size']:
                        if result['obj_size'] > 0:
                            if segmented.get(obj['name']):
                                result['match'] = True
                            else:
                                result['file_hash'] = md5hash(path)
                                if result['file_hash'] == result['object_hash']:
                                    result['match'] = True
                        elif result['obj_size'] == 0:
                            result['match'] = True
                        else:
                            raise ValueError('Invalid object size:' + result['obj_size'])
                else:
                    raise ValueError(path + ' is not a regular file or directory.')
        return result

    connection = swiftclient.Connection(authurl=auth_url, auth_version=auth_version, user=username, key=password,
                                        tenant_name=tenant_name, insecure=insecure,
                                        os_options={'region_name': region_name})
    try:
        objects = connection.get_container(container_name, prefix=prefix, full_listing=full_listing)[1]
        if prefix is not None:
            objects.extend(
                connection.get_container(container_name, prefix=SEGMENT_PREFIX + prefix, full_listing=full_listing)[
                    1])
        i = 0
        n = len(objects)
        segmented = {}
        while i < n:
            obj = objects[i]
            if obj['name'].startswith(SEGMENT_PREFIX):
                obj_name, seg_idx = parse_segment_name(obj['name'])
                segmented[obj_name] = True
                obj['obj_name'] = obj_name
                obj['seg_idx'] = seg_idx
                if seg_idx == 1:
                    obj['seg_offset'] = 0
                else:
                    assert seg_idx - 1 == objects[i - 1]['seg_idx']
                    obj['seg_offset'] = objects[i - 1]['seg_offset'] + objects[i - 1]['bytes']
                obj['total_size'] = obj['seg_offset'] + obj['bytes']
                j = i - seg_idx + 1
                while j < i:
                    objects[j]['total_size'] = obj['total_size']
                    j += 1
            i += 1
    finally:
        connection.close()
    with cfutures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check, obj, root, segmented) for obj in objects}
        for future in cfutures.as_completed(futures):
            print future.result()


def swift_list(auth_url, username, password, tenant_name, container_name, auth_version='2', insecure=False,
               region_name=None,
               prefix=None, full_listing=True, func=None):
    connection = swiftclient.Connection(authurl=auth_url, auth_version=auth_version, user=username, key=password,
                                        tenant_name=tenant_name, insecure=insecure,
                                        os_options={'region_name': region_name})
    try:
        container = connection.get_container(container_name, prefix=prefix, full_listing=full_listing)[1]
        if prefix is not None:
            container += \
                connection.get_container(container_name, prefix=SEGMENT_PREFIX + prefix, full_listing=full_listing)[
                    1]
    finally:
        connection.close()
    for obj in container:
        if func is None:
            print obj
        else:
            func(obj)


def md5hash(f, offset=0, length=0, buffer_size=65536):
    if isinstance(f, str) or isinstance(f, unicode):
        with open(f, 'rb') as o:
            return md5hash(o, offset, length, buffer_size)
    hasher = hashlib.md5()
    if offset > 0:
        f.seek(offset)
    if length > 0:
        total_read = 0
        while length > total_read:
            if total_read + buffer_size < length:
                buff = f.read(buffer_size)
            else:
                buff = f.read(length - total_read)
            hasher.update(buff)
            total_read += len(buff)
    else:
        while True:
            buff = f.read(buffer_size)
            if len(buff) > 0:
                hasher.update(buff)
            else:
                break
    return hasher.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth-url", help="auth url", default=os.environ.get('OS_AUTH_URL'))
    parser.add_argument("--auth-version", help="auth version", default='2')
    parser.add_argument("--username", help="user name", default=os.environ.get('OS_USERNAME'))
    parser.add_argument("--password", help="key/password", default=os.environ.get('OS_PASSWORD'))
    parser.add_argument("--tenant-name", help="tenant name", default=os.environ.get('OS_TENANT_NAME'))
    parser.add_argument("--region-name", help="region name", default=os.environ.get('OS_REGION_NAME'))
    parser.add_argument("--insecure", help="allow untrusted ssl certs", action="store_true", default=True)
    parser.add_argument("--full-listing", help="list all objects in the container", action="store_true", default=True)
    parser.add_argument("--prefix", help="prefix", default=None)
    parser.add_argument("container", help="container name")
    parser.add_argument("root", help="local root directory")
    args = parser.parse_args()
    swift_check(args.root, args.auth_url, args.username, args.password, args.tenant_name, args.container,
                auth_version=args.auth_version, insecure=args.insecure, region_name=args.region_name,
                prefix=args.prefix,
                full_listing=args.full_listing)
