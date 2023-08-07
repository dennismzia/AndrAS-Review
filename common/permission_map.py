# Permissions and API calls mapping
# Map permission to description of API calls
PERMISSION_ZONE = {
    'android.permission.INTERNET' : ["HTTP Url Connection", 
                                    "HTTPS Url Connection", 
                                    "Retrofit Connection",
                                    "Volley Connection",
                                    "OkHttpClient Connection",
                                    "DefaultHttpClient Connection",
                                    "AndroidHttpClient Connection"],
    'android.permission.NFC' : ["NFC Connection"],
    'android.permission.BLUETOOTH' : ["Bluetooth Connection"],
    'android.permission.BLUETOOTH_ADMIN' : ["Bluetooth Connection"],
    'android.permission.BLUETOOTH_SCAN' : ["Bluetooth Connection"],
    'android.permission.BLUETOOTH_ADVERTISE' : ["Bluetooth Connection"],
    'android.permission.BLUETOOTH_CONNECT' : ["Bluetooth Connection"],
    'Local App' : ["SQLite Databases", 
                "Shared Preferences", 
                "Realm Databases",
                "Internal Storage", 
                "External Storage"],
    'Android Scope' : ["Room Databases", "Media Storage"],
    'android.permission.SEND_SMS' : ["Sending SMS"],
    #'android.permission.RECEIVE_SMS' : ["api_sms_receiving"],
    'android.permission.READ_EXTERNAL_STORAGE' : ["Sending SMS", "Media Storage"],
    'android.permission.CAMERA' : ['Camera'],
    'android.permission.ACCESS_FINE_LOCATION': ["Location Service", "Bluetooth Connection"],
    'android.permission.ACCESS_COARSE_LOCATION' : ["Location Service"]
}


API_CALLS_PERMISSIONS = {'HTTP Url Connection': ['android.permission.INTERNET'], 
                        'HTTPS Url Connection': ['android.permission.INTERNET'], 
                        'Retrofit Connection': ['android.permission.INTERNET'], 
                        'Volley Connection': ['android.permission.INTERNET'], 
                        'OkHttpClient Connection': ['android.permission.INTERNET'], 
                        'DefaultHttpClient Connection': ['android.permission.INTERNET'], 
                        'AndroidHttpClient Connection': ['android.permission.INTERNET'], 
                        'WebView Connection': ['android.permission.INTERNET'],
                        'NFC Connection': ['android.permission.NFC'], 
                        'Bluetooth Connection': ['android.permission.BLUETOOTH', 'android.permission.BLUETOOTH_ADMIN', 'android.permission.BLUETOOTH_SCAN', 'android.permission.BLUETOOTH_ADVERTISE', 'android.permission.BLUETOOTH_CONNECT', 'android.permission.ACCESS_FINE_LOCATION'], 
                        # 'SQLite Databases': ['Local App'], 
                        # 'Shared Preferences': ['Local App'], 
                        # 'Realm Databases': ['Local App'], 
                        # 'Internal Storage': ['Local App'], 
                        # 'External Storage': ['Local App'], 
                        # 'DataStore': ['Local App'],
                        # 'Media Storage': ['Android OS', 'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE'], 
                        #'Documents': ['Android OS'],
                        'SMS': ['android.permission.SEND_SMS', 'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.READ_PHONE_STATE'], 
                        'Camera': ['android.permission.CAMERA'], 
                        'Location Service': ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION'],
                        'Socket Connection':['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
                        'SSL Socket Connection':['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
                        'Contacts': ['android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS'],
                        'Calendar': ['android.permission.READ_CALENDAR', 'android.permission.WRITE_CALENDAR'],
                        #'Sensors': ['Android OS']
                        }

TRUST_BOUNDARY = {"Local App": ['SQLite Databases', 'Shared Preferences', 'Realm Databases', 
                                'Internal Storage', 'External Storage', 'DataStore', 'Media Storage', 'Documents'],
                "Android OS": ['Contacts', 'Calendar', 'Sensors', 'SSL Socket Connection', 'Socket Connection', 'SMS', 'Camera', 'Location Service'],
                "External Scope": ['HTTP Url Connection', 'HTTPS Url Connection', 'Retrofit Connection', 
                                   'Volley Connection', 'OkHttpClient Connection', 'DefaultHttpClient Connection', 
                                   'AndroidHttpClient Connection', 'WebView Connection', 'NFC Connection', 
                                   'Bluetooth Connection']}