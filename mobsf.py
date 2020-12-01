import os, hashlib

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import ProcessingModule

class Mobsf_module(ProcessingModule):

    name = "MobSF"
    description = "send to analyze APK to MobSF platform."
    config = [
        {
            'name': 'url_upload',
            'type': 'string',
            'description': 'URL needed to use the MobSF Public API',
        },
        {
            'name': 'url_scan',
            'type': 'string',
            'description': 'URL needed to use the MobSF Public API',
        },
        {
            'name': 'web_path_static_analyze',
            'type': 'string',
            'description': 'URL needed to use the MobSF Public API',
        },
        {
            'name': 'api_key',
            'type': 'string',
            'description': 'Needed to use the MobSF Public API',
        }
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, 'Missing dependency: requests')

        return True

    def each_with_type(self, target, file_type):
        # Set root URLs
        self.results = dict()

        if file_type == 'apk':
            headers = {'Authorization': self.api_key}
            files = {'file': (target, open(target,'rb'), 'application/octet-stream')}
            r = requests.post(self.url_upload, headers=headers, files=files)
            if r.status_code == 200:
                response = r.json()
                r2 = requests.post(self.url_scan, headers=headers, data={'scan_type': response['scan_type'], 'hash': response['hash'], 'file_name': response['file_name']})
                if r2.status_code == 200:
                    md5hash = r2.json()['md5']
                    self.web_path_static_analyze = self.web_path_static_analyze + "name={0}&type={1}&checksum={2}".format(response['file_name'], response['scan_type'], md5hash)
                    self.results['permalink'] = self.web_path_static_analyze
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
