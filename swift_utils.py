import swiftclient
import hashlib
import threading
import os
import concurrent.futures as cfutures

SWIFT_SEGMENT_PREFIX = '.file-segments/'


def md5hash(f, offset=0, length=0, buffer_size=65536):
    """ Generate MD5 hash for specified file (chuck).
    :param f: file path or file object.
    :param offset: offset.
    :param length: length.
    :param buffer_size: buffer size. Defaults to 65536.
    :return: MD5 hash string
    """
    if isinstance(f, str) or isinstance(f, unicode):
        with open(f, 'rb') as o:
            return md5hash(o, offset, length, buffer_size)
    hasher = hashlib.md5()
    if offset > 0:  # chunked
        f.seek(offset)
    if length > 0:  # chunked
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


class SwiftChecker(object):
    """
    A class to validate files downloaded from (or uploaded to) swift storage.
    """

    def __init__(self, auth_url, username, password, tenant_name, auth_version='2', insecure=False,
                 region_name=None):
        """
        Constructor.
        :param auth_url: swift authurl
        :param username: swift username
        :param password: swift password (key)
        :param tenant_name: swift tenant name
        :param auth_version: swift auth version. Defaults to 2.
        :param insecure: allow untrusted SSL connection.
        :param region_name: swift region name. (Required for auth version 2.)
        """
        self._auth_url = auth_url
        self._auth_version = auth_version
        self._username = username
        self._password = password
        self._tenant_name = tenant_name
        self._region_name = region_name
        self._insecure = insecure

    def _connect(self):
        """
        Connect to swift server.
        :return: swiftclient connection
        """
        return swiftclient.Connection(authurl=self._auth_url, auth_version=self._auth_version,
                                      user=self._username, key=self._password,
                                      tenant_name=self._tenant_name, insecure=self._insecure,
                                      os_options={'region_name': self._region_name})

    def _list_objects(self, container_name, prefix=None, full_listing=True):
        """
        Get the list of objects.
        :param container_name:
        :param prefix:
        :param full_listing:
        :return: tuple: (objects, segmented), where 'objects' is the list of objects . Each object is a dictionary.
        'segmented' is the map (dict) of all the segmented objects.
        """
        connection = self._connect()  # create a swift connection
        try:
            objects = connection.get_container(container_name, prefix=prefix, full_listing=full_listing)[1]
            if prefix is not None:
                # prefix is specified. Add segments assoicated with the objects
                objects += \
                    connection.get_container(container_name, prefix=SWIFT_SEGMENT_PREFIX + prefix,
                                             full_listing=full_listing)[1]
            # insert extra elements to the dictionary (object record) to hold the segment offset, index, etc
            i = 0
            n = len(objects)
            segmented = {}  # a map to check if an object is segmented.
            while i < n:
                obj = objects[i]
                if obj['name'].startswith(SWIFT_SEGMENT_PREFIX):
                    obj_name, seg_idx = self._parse_segment_name(obj['name'])
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
            return objects, segmented
        finally:
            connection.close()

    @classmethod
    def _parse_segment_name(cls, name):
        """
        Parse object name for the specified segment name.
        :param name:
        :return: the object name
        """
        obj_name = name[len(SWIFT_SEGMENT_PREFIX):]
        idx1 = obj_name.rfind('/')
        seg_idx = int(obj_name[idx1 + 1:])
        obj_name = obj_name[:idx1]
        idx2 = obj_name.rfind('/')
        obj_name = obj_name[:idx2]
        return obj_name, seg_idx

    @classmethod
    def _check_object(cls, obj, dir, segmented):
        # initialise the result dict
        result = {'thread': threading.current_thread().getName(), 'obj_name': obj['name'],
                  'obj_size': obj['bytes'], 'obj_hash': obj['hash'], 'segment_info': None,
                  'file_path': None, 'file_type': 'file', 'file_size': 0, 'file_hash': None, 'file_exists': False,
                  'match': False}
        path = dir + ('' if dir.endswith('/') else '/')
        if obj['name'].startswith(SWIFT_SEGMENT_PREFIX):  # it is a segment object
            result['segment_info'] = {'object': obj['obj_name'], 'index': obj['seg_idx'], 'offset': obj['seg_offset'],
                                      'length': obj['bytes'], 'total': obj['total_size']}
            path += obj['obj_name']
            result['file_path'] = path
            if os.path.exists(path):  # check if the corresponding file exist locally
                result['file_exists'] = True
                if os.path.isfile(path):
                    result['file_type'] = 'file'
                    result['file_size'] = os.path.getsize(path)
                else:
                    raise ValueError(path + ' is not a regular file.')
                # calculate md5 hash of the local file
                result['file_hash'] = md5hash(path, result['segment_info']['offset'], result['segment_info']['length'])
                if result['file_hash'] == result['obj_hash']:  # check if the md5 hash match
                    result['match'] = True
        else:  # regular object (not segment)
            path += obj['name']
            result['file_path'] = path
            if os.path.exists(path):  # check if the corresponding file exist locally
                result['file_exists'] = True
                if os.path.isdir(path) and obj['bytes'] == 0:  # check if it is a directory (object)
                    result['file_type'] = 'directory'
                    result['file_size'] = 0
                    result['match'] = True
                elif os.path.isfile(path):
                    result['file_type'] = 'file'
                    result['file_size'] = os.path.getsize(path)
                    if result['obj_size'] == result['file_size']:  # check if file size match
                        if result['obj_size'] > 0:
                            if segmented.get(obj['name']):
                                result['match'] = True  # overall (segmented) object
                            else:
                                result['file_hash'] = md5hash(path)
                                if result['file_hash'] == result['obj_hash']:
                                    result['match'] = True
                        elif result['obj_size'] == 0:
                            result['match'] = True  # zero size file or directory
                        else:
                            raise ValueError('Invalid object size:' + result['obj_size'])
                else:
                    raise ValueError(path + ' is not a regular file or directory.')
        return result

    def check_download(self, container_name, dir, prefix=None, max_threads=5, func=None):
        objects, segmented = self._list_objects(container_name, prefix=prefix, full_listing=True)
        with cfutures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self._check_object, obj, dir, segmented) for obj in objects}
            for future in cfutures.as_completed(futures):
                if func:
                    func(future.result())
                else:
                    print(future.result())

    @classmethod
    def _check_file(cls, dir, path, map, segmented):
        assert os.path.exists(path) and os.path.isfile(path) and path.startswith(dir)

        dir = os.path.abspath(dir)
        path = os.path.abspath(path)
        file_size = os.path.getsize(path)
        obj_name = path[len(dir) + 1:]
        result = {'thread': threading.current_thread().getName(), 'obj_name': obj_name,
                  'obj_size': None, 'obj_hash': None, 'segment_info': None,
                  'file_path': path, 'file_type': 'file', 'file_size': file_size, 'file_hash': None,
                  'obj_exists': False, 'match': False}
        obj = map.get(obj_name)
        if not obj:
            # no corresponding object found in swift
            return result
        result['obj_exists'] = True
        result['obj_size'] = obj['bytes']
        if file_size != obj['bytes']:
            # file size not match
            return result
        if segmented.get(obj_name):
            obj_segments = {}
            for k in map:
                if k.startswith(SWIFT_SEGMENT_PREFIX + obj_name):
                    v = map.get(k)
                    obj_segments[v['seg_idx']] = v
            if len(obj_segments) == 0:
                raise ValueError("No segments found for " + obj_name)
            result['match'] = True
            for obj_segment in obj_segments:
                file_segment_hash = md5hash(path, offset=obj_segment['seg_offset'], length=obj_segment['bytes'])
                if obj_segment['hash'] != file_segment_hash:
                    result['match'] = False
                if obj_segment['total_size'] != obj['bytes']:
                    raise ValueError('Missing segments!')
        else:
            result['obj_hash'] = obj['hash']
            result['file_hash'] = md5hash(path)
            if result['obj_hash'] == result['file_bash']:
                result['match'] = True
        return result

    def check_upload(self, dir, container_name, prefix=None, max_threads=5, func=None):
        objects, segmented = self._list_objects(container_name, prefix=prefix, full_listing=True)
        map = {obj['name']: obj for obj in objects}
        with cfutures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = set()
            for (root, dirs, files) in os.walk(dir):
                for f in files:
                    path = os.path.join(root, f)
                    futures.add(executor.submit(self._check_file, dir, path, map, segmented))
            for future in cfutures.as_completed(futures):
                if func:
                    func(future.result())
                else:
                    print(future.result())
