import React, { useState } from 'react';
import { ChevronDown, Send, CheckCircle, XCircle } from 'lucide-react';

const DpapiSubmitCredential = () => {
  const [credentialType, setCredentialType] = useState('password');
  const [credentialValue, setCredentialValue] = useState('');
  const [userSid, setUserSid] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  const credentialTypes = [
    {
      value: 'password',
      label: 'Password',
      placeholder: 'Password123!',
      apiType: 'password'
    },
    {
      value: 'ntlm_hash',
      label: 'NTLM hash',
      placeholder: '2B576ACBE6BCFDA7294D6BD18041B8FE',
      apiType: 'ntlm_hash'
    },
    {
      value: 'cred_key',
      label: 'Cred Key',
      placeholder: '9c457aaadf804b08db137f1bc40dcc46',
      apiType: 'cred_key'
    },
    {
      value: 'domain_backup_key',
      label: 'Domain Backup Key',
      placeholder: 'AgAAAAAAAAAAAAAANgBjADIAYg... (base64(pvk))',
      apiType: 'domain_backup_key'
    },
    {
      value: 'dec_master_key',
      label: 'Decrypted Master Key',
      placeholder: '{6d2bd107-a942-4c0d-bf2a-8b3d1264cf73}:0826EC6BC801252E401902AB09FE1068052D07001',
      apiType: 'dec_master_key'
    }
  ];

  const selectedType = credentialTypes.find(type => type.value === credentialType);
  const requiresUserSid = ['password', 'ntlm_hash', 'cred_key'].includes(credentialType);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!credentialValue.trim()) {
      setMessage({ type: 'error', text: 'Please enter a credential value' });
      return;
    }

    if (requiresUserSid && !userSid.trim()) {
      setMessage({ type: 'error', text: 'Please enter a User SID' });
      return;
    }

    setIsSubmitting(true);
    setMessage({ type: '', text: '' });

    try {
      const response = await fetch('/api/dpapi/credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: selectedType.apiType,
          value: encodeURIComponent(credentialValue),
          ...(requiresUserSid && { user_sid: userSid })
        }),
      });

      if (response.ok) {
        setMessage({ type: 'success', text: 'Credential submitted successfully!' });
        setCredentialValue('');
        setUserSid('');
      } else {
        let errorMessage = `HTTP ${response.status}`;
        try {
          const errorData = await response.json();
          if (errorData.message) {
            errorMessage = errorData.message;
          } else if (errorData.detail) {
            errorMessage = errorData.detail;
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
          text: `Failed to submit credential: ${errorMessage}` 
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
                  setMessage({ type: '', text: '' });
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

          {/* Credential Value Input */}
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

          {/* Submit Button */}
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={isSubmitting || !credentialValue.trim() || (requiresUserSid && !userSid.trim())}
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
          <div className={`mt-4 p-4 rounded-md flex items-center ${
            message.type === 'success'
              ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700'
              : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700'
          }`}>
            {message.type === 'success' ? (
              <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 mr-2 flex-shrink-0" />
            ) : (
              <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 mr-2 flex-shrink-0" />
            )}
            <p className={`text-sm ${
              message.type === 'success'
                ? 'text-green-800 dark:text-green-200'
                : 'text-red-800 dark:text-red-200'
            }`}>
              {message.text}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default DpapiSubmitCredential;