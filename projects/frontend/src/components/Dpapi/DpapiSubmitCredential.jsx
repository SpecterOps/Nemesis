import React, { useState } from 'react';
import { ChevronDown, Send, CheckCircle, XCircle } from 'lucide-react';

const DpapiSubmitCredential = () => {
  const [credentialType, setCredentialType] = useState('password');
  const [credentialValue, setCredentialValue] = useState('');
  const [userSid, setUserSid] = useState('');
  const [guid, setGuid] = useState('');
  const [domainController, setDomainController] = useState('');
  const [masterKeyData, setMasterKeyData] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '', details: null });
  const [showDetails, setShowDetails] = useState(false);

  const credentialTypes = [
    {
      value: 'password',
      label: 'Password',
      placeholder: 'Password123!',
      apiType: 'password',
      description: 'Specify a SID and password to decrypt master keys associated with a user account. Collect it potentially from users (ask them), LSASS memory dumps (if the user is logged in and the OS supports stores it), keylogging, password managers, files (e.g. on disk, in shares, source code repositories), etc.'
    },
    {
      value: 'cred_key_ntlm',
      label: 'NTLM Hash',
      placeholder: 'ABD9FFB762C86B26EF4CE5C81B0DD37F (16 bytes)',
      apiType: 'cred_key_ntlm',
      description: 'Specify a SID and NTLM hash to decrypt master keys associated with a user account. Generate it by taking the MD4 hash of the password. Collect it from LSASS memory dumps (if the user is logged in and the OS supports stores it), by obtaining and/or cracking an NTLMv1 hash (e.g., using Internal-Monologue or coercing authentication on a machine with NTLMv1 enabled), by extracting it from the SAM & SYSTEM registry hives (for local accounts only), and from NTDS databases(ntds.dit+SYSTEM hive, dcsync, DSInternals, etc).'
    },
    {
      value: 'cred_key_sha1',
      label: 'SHA1',
      placeholder: 'ABCDEF1234567890ABCDEF1234567890ABCDEF12 (20 bytes)',
      apiType: 'cred_key_sha1',
      description: 'Specify a SID and SHA1 credential key (a 20-byte key) to decrypt master keys associated with a user account. Generate it by taking the SHA1 hash of an NTLM hash. If the user is logged in, collect it from LSASS memory dumps or from the msv1_0 authentication package using LSA Whisperer\'s msv1_0!GetCredentialKey or msv1_0!GetStrongCredentialKey commands.'
    },
    {
      value: 'cred_key_pbkdf2',
      label: 'Secure Credential Key (PBKDF2)',
      placeholder: 'ABCDEF1234567890ABCDEF1234567890ABCDEF12 (16 bytes)',
      apiType: 'cred_key_pbkdf2',
      description: 'Specify a SID and secure credential key (a 16-byte key derived using PBKDF2) to decrypt master keys associated with a user account.  If the user is logged in, collect it from LSASS memory dumps or from the msv1_0 authentication package using LSA Whisperer\'s msv1_0!GetCredentialKey or msv1_0!GetStrongCredentialKey commands.'
    },
    {
      value: 'domain_backup_key',
      label: 'Domain Backup Key',
      placeholder: 'AgAAAAAAAAAAAAAANgBjADIAYg... (base64(pvk))',
      apiType: 'domain_backup_key',
      requiresGuid: true,
      supportsDomainController: true,
      description: 'Domain controller DPAPI backup key in base64 PVK format. Extract from domain controllers using tools like mimikatz\'s lsadump::backupkeys, SharpDPAPI\s backupkey command, or by accessing the DPAPI_SYSTEM LSA secret on a host.'
    },
    {
      value: 'master_key_guid_pair',
      label: 'Master Keys GUID:SHA1 Pairs',
      placeholder: 'Enter master key data (one per line)\n{guid}:{sha1}\n{guid}:{sha1}',
      apiType: 'master_key_guid_pair',
      structuredValue: true,
      description: 'Plaintext DPAPI master keys as GUID:SHA1 pairs.'
    },
    {
      value: 'dpapi_system',
      label: 'DPAPI_SYSTEM Secret',
      placeholder: 'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890',
      apiType: 'dpapi_system',
      description: 'System DPAPI credential used for machine-wide encryption. Collect from the DPAPI_SYSTEM LSA secret (e.g., via the SYSTEM and SECURITY registry hives) or using the LSA APIs (e.g. using mimikatz\s lsadump::secrets command).'
    }
  ];

  const selectedType = credentialTypes.find(type => type.value === credentialType);
  const requiresUserSid = ['password', 'cred_key_ntlm', 'cred_key_sha1', 'cred_key_pbkdf2'].includes(credentialType);
  const requiresGuid = selectedType?.requiresGuid || false;
  const supportsDomainController = selectedType?.supportsDomainController || false;
  const isStructuredValue = selectedType?.structuredValue || false;

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (isStructuredValue) {
      if (!masterKeyData.trim()) {
        setMessage({ type: 'error', text: 'Please enter master key data' });
        return;
      }

      // Validate master key data format
      const lines = masterKeyData.split('\n').filter(line => line.trim());
      const uuidRegex = /^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$/;
      const hexRegex = /^[0-9a-fA-F]+$/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const parts = line.split(':');

        if (parts.length !== 2) {
          setMessage({
            type: 'error',
            text: `Line ${i + 1}: Invalid format. Expected "guid:sha1hex"`
          });
          return;
        }

        const [guid, keyHex] = parts;

        if (!uuidRegex.test(guid)) {
          setMessage({
            type: 'error',
            text: `Line ${i + 1}: Invalid GUID format "${guid}"`
          });
          return;
        }

        if (!hexRegex.test(keyHex)) {
          setMessage({
            type: 'error',
            text: `Line ${i + 1}: Invalid hex format in key "${keyHex}"`
          });
          return;
        }
      }
    } else {
      if (!credentialValue.trim()) {
        setMessage({ type: 'error', text: 'Please enter a credential value' });
        return;
      }
    }

    if (requiresUserSid && !userSid.trim()) {
      setMessage({ type: 'error', text: 'Please enter a User SID' });
      return;
    }

    setIsSubmitting(true);
    setMessage({ type: '', text: '', details: null });

    try {
      const response = await fetch('/api/dpapi/credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: selectedType.apiType,
          ...(isStructuredValue ? {
            value: masterKeyData.split('\n')
              .filter(line => line.trim())
              .map(line => {
                const [guid, key_hex] = line.trim().split(':');
                return { guid, key_hex };
              })
          } : {
            value: credentialValue
          }),
          ...(requiresUserSid && { user_sid: userSid }),
          ...(requiresGuid && guid.trim() && { guid }),
          ...(supportsDomainController && domainController.trim() && { domain_controller: domainController })
        }),
      });

      if (response.ok) {
        const responseData = await response.json();
        let successMessage = 'Credential submitted successfully!';
        let details = null;

        if (responseData && Object.keys(responseData).length > 0) {
          const filteredData = Object.entries(responseData)
            .filter(([, value]) => value !== null && value !== undefined && value !== '')
            .reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {});

          if (Object.keys(filteredData).length > 0) {
            details = filteredData;
          }
        }

        setMessage({ type: 'success', text: successMessage, details });
        setShowDetails(false);
        setCredentialValue('');
        setUserSid('');
        setGuid('');
        setDomainController('');
        setMasterKeyData('');
      } else {
        let errorMessage = `HTTP ${response.status}`;
        let errorDetails = null;
        try {
          const errorData = await response.json();
          if (errorData.message) {
            errorMessage = errorData.message;
          } else if (errorData.detail) {
            // Handle validation errors (array of error objects)
            if (Array.isArray(errorData.detail)) {
              errorMessage = 'Validation error';
              errorDetails = errorData.detail;
            } else {
              errorMessage = errorData.detail;
            }
          } else if (errorData.error) {
            errorMessage = errorData.error;
          } else {
            errorMessage = `${errorMessage} - ${response.statusText}`;
          }
        } catch {
          // If JSON parsing fails, include status text
          errorMessage = `${errorMessage} - ${response.statusText}`;
        }
        setMessage({
          type: 'error',
          text: `Failed to submit credential: ${errorMessage}`,
          details: errorDetails
        });
      }
    } catch (error) {
      setMessage({
        type: 'error',
        text: `Network error: ${error.message}`
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-6">
      <div className="max-w-3xl mx-auto">
        {/* Description */}
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
          <p className="text-blue-800 dark:text-blue-200 text-sm">
            Input additional credential material to decrypt any existing DPAPI master keys.
          </p>
          <p className="text-blue-800 dark:text-blue-200 text-sm mt-2 font-bold italic">
            Note: this will only decrypt currently stored masterkeys, not future entries!
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Credential Type Dropdown */}
          <div>
            <label htmlFor="credential-type" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Credential Type
            </label>
            <div className="relative">
              <select
                id="credential-type"
                value={credentialType}
                onChange={(e) => {
                  setCredentialType(e.target.value);
                  setCredentialValue('');
                  setUserSid('');
                  setGuid('');
                  setDomainController('');
                  setMasterKeyData('');
                  setMessage({ type: '', text: '', details: null });
                  setShowDetails(false);
                }}
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-dark-secondary rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-gray-100 appearance-none pr-10"
              >
                {credentialTypes.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-2.5 h-5 w-5 text-gray-400 pointer-events-none" />
            </div>
          </div>

          {/* Credential Type Description */}
          {selectedType?.description && (
            <p className="text-sm text-gray-600 dark:text-gray-400 -mt-1 mb-4">
              {selectedType.description}
            </p>
          )}

          {/* User SID Input - Only for password, ntlm_hash, cred_key */}
          {requiresUserSid && (
            <div>
              <label htmlFor="user-sid" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                User SID
              </label>
              <input
                type="text"
                id="user-sid"
                value={userSid}
                onChange={(e) => setUserSid(e.target.value)}
                placeholder="S-1-5-21-2193901138-2161926575-8610939201-1000"
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-dark-secondary rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500"
                required
              />
            </div>
          )}

          {/* GUID Input - For domain_backup_key */}
          {requiresGuid && (
            <div>
              <label htmlFor="guid" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Backup Key GUID
              </label>
              <input
                type="text"
                id="guid"
                value={guid}
                onChange={(e) => setGuid(e.target.value)}
                placeholder="6d2bd107-a942-4c0d-bf2a-8b3d1264cf73"
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-dark-secondary rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500"
                required
              />
            </div>
          )}

          {/* Domain Controller Input - Optional for domain_backup_key */}
          {supportsDomainController && (
            <div>
              <label htmlFor="domain-controller" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Domain Controller (Optional)
              </label>
              <input
                type="text"
                id="domain-controller"
                value={domainController}
                onChange={(e) => setDomainController(e.target.value)}
                placeholder="dc.domain.com"
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-dark-secondary rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500"
              />
            </div>
          )}

          {/* Master Key Data - For master_key_guid_pair */}
          {isStructuredValue && (
            <div>
              <label htmlFor="master-key-data" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Master Key Data
              </label>
              <textarea
                id="master-key-data"
                value={masterKeyData}
                onChange={(e) => setMasterKeyData(e.target.value)}
                placeholder={`6d2bd107-a942-4c0d-bf2a-8b3d1264cf73:0826EC6BC801252E401902AB09FE1068052D07001
12345678-1234-1234-1234-123456789012:ABCDEF1234567890ABCDEF1234567890ABCDEF12`}
                rows={6}
                className="block w-full px-1 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-dark-secondary rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 resize-vertical font-mono"
                required
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Format: One entry per line in the format "{"{guid}"}:{"{sha1}"}"
              </p>
            </div>
          )}

          {/* Credential Value Input - For other types */}
          {!isStructuredValue && (
            <div>
              <label htmlFor="credential-value" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Credential Value
              </label>
              <textarea
                id="credential-value"
                value={credentialValue}
                onChange={(e) => setCredentialValue(e.target.value)}
                placeholder={selectedType?.placeholder}
                rows={4}
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-dark-secondary rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 resize-vertical"
              />
            </div>
          )}

          {/* Submit Button */}
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={
                isSubmitting ||
                (isStructuredValue ? !masterKeyData.trim() : !credentialValue.trim()) ||
                (requiresUserSid && !userSid.trim()) ||
                (requiresGuid && !guid.trim())
              }
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isSubmitting ? (
                <>
                  <div className="animate-spin -ml-1 mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                  Submitting...
                </>
              ) : (
                <>
                  <Send className="-ml-1 mr-2 h-4 w-4" />
                  Submit Credential
                </>
              )}
            </button>
          </div>
        </form>

        {/* Success/Error Messages */}
        {message.text && (
          <div className={`mt-4 rounded-md ${
            message.type === 'success'
              ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700'
              : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700'
          }`}>
            <div className="p-4 flex items-center">
              {message.type === 'success' ? (
                <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 mr-2 flex-shrink-0" />
              ) : (
                <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 mr-2 flex-shrink-0" />
              )}
              <div className="flex-1">
                <p className={`text-sm ${
                  message.type === 'success'
                    ? 'text-green-800 dark:text-green-200'
                    : 'text-red-800 dark:text-red-200'
                }`}>
                  {message.text}
                </p>
                {message.details && (
                  <button
                    onClick={() => setShowDetails(!showDetails)}
                    className={`mt-2 text-xs underline hover:no-underline ${
                      message.type === 'success'
                        ? 'text-green-600 dark:text-green-400'
                        : 'text-red-600 dark:text-red-400'
                    }`}
                  >
                    {showDetails ? 'Hide' : 'Show'} response details
                  </button>
                )}
              </div>
            </div>
            {message.details && showDetails && (
              <div className={`px-4 pb-4 border-t ${
                message.type === 'success'
                  ? 'border-green-200 dark:border-green-700'
                  : 'border-red-200 dark:border-red-700'
              }`}>
                <pre className={`text-xs mt-2 whitespace-pre-wrap font-mono ${
                  message.type === 'success'
                    ? 'text-green-700 dark:text-green-300'
                    : 'text-red-700 dark:text-red-300'
                }`}>
                  {JSON.stringify(message.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default DpapiSubmitCredential;