import Tooltip from '@/components/shared/Tooltip';
import { useTheme } from '@/components/ThemeProvider';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useUser } from '@/contexts/UserContext';
import Editor from "@monaco-editor/react";
import { ChevronDown, Plus, Tag, X } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const FileDetailsSection = ({ fileData, setFileData }) => {
  const navigate = useNavigate();
  const { isDark } = useTheme();
  const { username } = useUser();
  const editorRef = useRef(null);
  const [feedback, setFeedback] = useState({
    missing_parser: false,
    missing_file_viewer: false,
    sensitive_info_not_detected: false,
    comments: ''
  });

  const [isFirstInteraction, setIsFirstInteraction] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  const [editorValue, setEditorValue] = useState('');
  const placeholderText = "Add any additional comments here...";

  // New state for tags
  const [availableTags, setAvailableTags] = useState([]);
  const [newTagInput, setNewTagInput] = useState('');
  const [isTagDropdownOpen, setIsTagDropdownOpen] = useState(false);
  const [fileTags, setFileTags] = useState([]);
  const newTagInputRef = useRef(null);
  const tagDropdownRef = useRef(null);

  useEffect(() => {
    // Set initial tags from fileData
    if (fileData?.file_tags) {
      setFileTags(fileData.file_tags);
    }

    // Fetch existing feedback and available tags
    const fetchInitialData = async () => {
      try {
        await Promise.all([
          fetchExistingFeedback(),
          fetchAvailableTags()
        ]);
      } finally {
        setIsLoading(false);
      }
    };

    if (fileData?.object_id) {
      fetchInitialData();
    }
  }, [fileData?.object_id]);

  // Click outside to close dropdown
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (tagDropdownRef.current && !tagDropdownRef.current.contains(event.target)) {
        setIsTagDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const fetchExistingFeedback = async () => {
    const query = {
      query: `
        query GetFileFeedback($object_id: uuid!) {
          files_feedback(where: {object_id: {_eq: $object_id}}) {
            missing_parser
            missing_file_viewer
            sensitive_info_not_detected
            comments
            timestamp
            username
          }
        }
      `,
      variables: {
        object_id: fileData.object_id
      }
    };

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(query)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      if (result.data.files_feedback.length > 0) {
        const existingFeedback = result.data.files_feedback[0];
        const newFeedback = {
          missing_parser: existingFeedback.missing_parser || false,
          missing_file_viewer: existingFeedback.missing_file_viewer || false,
          sensitive_info_not_detected: existingFeedback.sensitive_info_not_detected || false,
          comments: existingFeedback.comments || ''
        };
        setFeedback(newFeedback);
        setEditorValue(existingFeedback.comments || placeholderText);
        setIsFirstInteraction(!existingFeedback.comments);
      } else {
        setEditorValue(placeholderText);
      }
    } catch (err) {
      console.error('Failed to fetch existing feedback:', err);
      setEditorValue(placeholderText);
    }
  };

  const fetchAvailableTags = async () => {
    const query = {
      query: `
        query GetAllTags {
          file_tags {
            tag_name
          }
        }
      `
    };

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(query)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      const tags = result.data.file_tags.map(tag => tag.tag_name);
      setAvailableTags(tags);
    } catch (err) {
      console.error('Failed to fetch available tags:', err);
    }
  };

  const handleAddTag = async (tagName) => {
    if (!tagName.trim() || fileTags.includes(tagName)) return;

    const newTags = [...fileTags, tagName];

    // Update local state immediately for responsive UI
    setFileTags(newTags);

    // If tag doesn't exist in available tags, add it
    if (!availableTags.includes(tagName)) {
      try {
        await createNewTag(tagName);
        setAvailableTags([...availableTags, tagName]);
      } catch (err) {
        console.error('Failed to create new tag:', err);
      }
    }

    // Update file record with new tags
    await updateFileTags(newTags);
    setNewTagInput('');
    setIsTagDropdownOpen(false);
  };

  const handleRemoveTag = async (tagToRemove) => {
    const newTags = fileTags.filter(tag => tag !== tagToRemove);
    setFileTags(newTags);
    await updateFileTags(newTags);
  };

  const createNewTag = async (tagName) => {
    const mutation = {
      query: `
        mutation CreateNewTag($tag_name: String!) {
          insert_file_tags_one(object: {tag_name: $tag_name}) {
            tag_name
          }
        }
      `,
      variables: {
        tag_name: tagName
      }
    };

    const response = await fetch('/hasura/v1/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
      },
      body: JSON.stringify(mutation)
    });

    if (!response.ok) throw new Error('Network error');

    const result = await response.json();
    if (result.errors) throw new Error(result.errors[0].message);

    return result.data.insert_file_tags_one;
  };

  const updateFileTags = async (tags) => {
    // In Hasura, array types often need specific handling
    const mutation = {
      query: `
        mutation UpdateFileTags($object_id: uuid!, $file_tags: [String]) {
          update_files_enriched_by_pk(
            pk_columns: {object_id: $object_id}, 
            _set: {file_tags: $file_tags}
          ) {
            object_id
            file_tags
          }
        }
      `,
      variables: {
        object_id: fileData.object_id,
        file_tags: tags
      }
    };

    try {
      console.log('Updating tags with mutation:', JSON.stringify(mutation));
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) {
        console.error('GraphQL errors:', result.errors);
        throw new Error(result.errors[0].message);
      }

      // Update parent state
      setFileData(prevData => ({
        ...prevData,
        file_tags: tags
      }));

      console.log('Tags updated successfully:', tags);

    } catch (err) {
      console.error('Failed to update file tags:', err);
      // Revert to previous tags on error
      setFileTags(fileData.file_tags || []);
    }
  };

  const handleEditorDidMount = (editor) => {
    editorRef.current = editor;

    editor.onDidFocusEditorWidget(() => {
      if (isFirstInteraction && editor.getValue() === placeholderText) {
        editor.setValue('');
        setEditorValue('');
        setIsFirstInteraction(false);
      }
    });

    editor.onDidBlurEditorWidget(() => {
      if (editor.getValue().trim() === '') {
        editor.setValue(placeholderText);
        setEditorValue(placeholderText);
        setIsFirstInteraction(true);
      }
    });

    editor.onDidChangeModelContent(() => {
      const value = editor.getValue();
      if (value !== placeholderText) {
        setFeedback(prev => ({ ...prev, comments: value }));
        setEditorValue(value);
      }
    });
  };

  const handleFeedback = async () => {
    const commentsToSave = editorValue === placeholderText ? '' : editorValue.trim();

    const mutation = {
      query: `
        mutation InsertFileFeedback($object_id: uuid!, $username: String!, $missing_parser: Boolean!, $missing_file_viewer: Boolean!, $sensitive_info_not_detected: Boolean!, $comments: String, $automated: Boolean!) {
          insert_files_feedback_one(
            object: {
              object_id: $object_id,
              username: $username,
              missing_parser: $missing_parser,
              missing_file_viewer: $missing_file_viewer,
              sensitive_info_not_detected: $sensitive_info_not_detected,
              comments: $comments,
              automated: $automated
            },
            on_conflict: {
              constraint: files_feedback_pkey,
              update_columns: [username, missing_parser, missing_file_viewer, sensitive_info_not_detected, comments, automated]
            }
          ) {
            object_id
            timestamp
          }
        }
      `,
      variables: {
        object_id: fileData.object_id,
        username: username,
        missing_parser: feedback.missing_parser,
        missing_file_viewer: feedback.missing_file_viewer,
        sensitive_info_not_detected: feedback.sensitive_info_not_detected,
        comments: commentsToSave,
        automated: false
      }
    };

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      // Update local state
      setFileData(prevData => ({
        ...prevData,
        files_feedback: {
          ...feedback,
          username,
          timestamp: new Date().toISOString()
        }
      }));

      console.log('Feedback recorded successfully');

    } catch (err) {
      console.error('Failed to record feedback:', err);
    }
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <Card className="bg-white dark:bg-dark-secondary shadow-lg mb-1 transition-colors">
      <CardHeader className="border-b border-gray-200 dark:border-gray-700 py-4">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-4">
            <CardTitle className="text-gray-900 dark:text-gray-100">File Details</CardTitle>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0 pb-0">
        <div className="grid grid-cols-2 gap-4">
          <div className="p-4">
            <table className="w-full">
              <tbody>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400 w-32">File Name</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.file_name}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400 w-32">Object ID</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.object_id}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Agent ID</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.agent_id}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Project</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.project}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Size</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{`${(fileData?.size / 1024).toFixed(2)} KB`}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Magic Type</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100 break-all">{fileData?.magic_type || 'Unknown'}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">MIME Type</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.mime_type || 'Unknown'}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Is Plaintext</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.is_plaintext ? 'Yes' : 'No'}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Is Container</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{fileData?.is_container ? 'Yes' : 'No'}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Upload Time</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{new Date(fileData?.timestamp).toLocaleString()}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Expiration</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100">{new Date(fileData?.expiration).toLocaleString()}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">MD5</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100 break-all">{fileData?.hashes?.md5}</td>
                </tr>
                <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">SHA1</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100 break-all">{fileData?.hashes?.sha1}</td>
                </tr>
                {/* <tr>
                  <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">SHA256</td>
                  <td className="py-0.5 font-mono text-sm text-gray-900 dark:text-gray-100 break-all">{fileData?.hashes?.sha256}</td>
                </tr> */}
                {fileData?.originating_object_id && (
                  <tr>
                    <td className="py-0.5 pr-4 text-gray-500 dark:text-gray-400">Originating File</td>
                    <td className="py-0.5 font-mono text-sm">
                      <button
                        onClick={() => navigate(`/files/${fileData.originating_object_id}`)}
                        className="text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        {fileData.originating_object_id}
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="p-4">
            {/* Tag management section (where hashes were previously) */}
            <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg mb-4">
              <div className="flex justify-between items-center mb-3">
                <h3 className="text-md font-medium text-gray-900 dark:text-gray-100 flex items-center">
                  <Tag className="w-4 h-4 mr-2" />
                  File Tags
                </h3>
                <div className="relative" ref={tagDropdownRef}>
                  <button
                    onClick={() => setIsTagDropdownOpen(!isTagDropdownOpen)}
                    className="flex items-center gap-1 px-3 h-8 bg-blue-600 dark:bg-blue-500 text-white text-sm rounded hover:bg-blue-700 dark:hover:bg-blue-600"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Add Tag</span>
                    <ChevronDown className="w-3 h-3 ml-1 opacity-80" />
                  </button>
                  {isTagDropdownOpen && (
                    <div className="absolute z-30 mt-1 right-0 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md shadow-lg w-64">
                      <div className="p-2">
                        <input
                          ref={newTagInputRef}
                          type="text"
                          value={newTagInput}
                          onChange={(e) => setNewTagInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              handleAddTag(newTagInput);
                            }
                          }}
                          placeholder="Type to create or filter tags..."
                          className="w-full p-2 text-sm border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                          autoFocus
                        />
                        <div className="max-h-48 overflow-y-auto">
                          {newTagInput && !availableTags.includes(newTagInput) && (
                            <button
                              onClick={() => handleAddTag(newTagInput)}
                              className="w-full text-left p-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 rounded flex items-center text-blue-600 dark:text-blue-400"
                            >
                              <Plus className="w-3 h-3 mr-2" />
                              Create "{newTagInput}"
                            </button>
                          )}
                          {availableTags
                            .filter(tag =>
                              !fileTags.includes(tag) &&
                              tag.toLowerCase().includes(newTagInput.toLowerCase())
                            )
                            .map(tag => (
                              <button
                                key={tag}
                                onClick={() => handleAddTag(tag)}
                                className="w-full text-left p-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 rounded text-gray-900 dark:text-white"
                              >
                                {tag}
                              </button>
                            ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {fileTags && fileTags.length > 0 ? (
                  fileTags.map(tag => {
                    // Generate a consistent color for each tag based on its name
                    const tagHash = tag.split('').reduce((acc, char) => char.charCodeAt(0) + acc, 0);

                    // Define an array of color classes (bg and text)
                    const colorClasses = [
                      { bg: "bg-blue-100 dark:bg-blue-900", text: "text-blue-800 dark:text-white", hover: "text-blue-600 dark:text-blue-300 hover:text-blue-800 dark:hover:text-white" },
                      { bg: "bg-green-100 dark:bg-green-900", text: "text-green-800 dark:text-white", hover: "text-green-600 dark:text-green-300 hover:text-green-800 dark:hover:text-white" },
                      { bg: "bg-purple-100 dark:bg-purple-900", text: "text-purple-800 dark:text-white", hover: "text-purple-600 dark:text-purple-300 hover:text-purple-800 dark:hover:text-white" },
                      { bg: "bg-red-100 dark:bg-red-900", text: "text-red-800 dark:text-white", hover: "text-red-600 dark:text-red-300 hover:text-red-800 dark:hover:text-white" },
                      { bg: "bg-amber-100 dark:bg-amber-900", text: "text-amber-800 dark:text-white", hover: "text-amber-600 dark:text-amber-300 hover:text-amber-800 dark:hover:text-white" },
                      { bg: "bg-indigo-100 dark:bg-indigo-900", text: "text-indigo-800 dark:text-white", hover: "text-indigo-600 dark:text-indigo-300 hover:text-indigo-800 dark:hover:text-white" },
                      { bg: "bg-teal-100 dark:bg-teal-900", text: "text-teal-800 dark:text-white", hover: "text-teal-600 dark:text-teal-300 hover:text-teal-800 dark:hover:text-white" },
                      { bg: "bg-pink-100 dark:bg-pink-900", text: "text-pink-800 dark:text-white", hover: "text-pink-600 dark:text-pink-300 hover:text-pink-800 dark:hover:text-white" }
                    ];

                    // Select a color class based on the tag hash
                    const colorIndex = tagHash % colorClasses.length;
                    const colorClass = colorClasses[colorIndex];

                    return (
                      <div
                        key={tag}
                        className={`flex items-center ${colorClass.bg} ${colorClass.text} px-3 py-1 rounded-full text-sm`}
                      >
                        <span>{tag}</span>
                        <button
                          onClick={() => handleRemoveTag(tag)}
                          className={`ml-1 ${colorClass.hover}`}
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-gray-500 dark:text-gray-400 text-sm italic">No tags added yet</p>
                )}
              </div>
            </div>

            <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg">
              <div className="flex flex-col space-y-4">

                <div className="grid grid-cols-3 gap-3">
                  <Tooltip content="Report that we need a structured parser for this particular file type.">
                    <button
                      onClick={() => setFeedback(prev => ({ ...prev, missing_parser: !prev.missing_parser }))}
                      className={`w-full p-3 rounded-lg transition-colors text-sm text-center ${feedback.missing_parser
                        ? 'bg-blue-100 dark:bg-blue-900 border-2 border-blue-500 dark:border-blue-400'
                        : 'bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                        }`}
                    >
                      <div className="font-medium text-gray-900 dark:text-gray-100">Missing Parser</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {feedback.missing_parser}
                      </div>
                    </button>
                  </Tooltip>

                  <Tooltip content="Report that we need a new type of file viewer (please provide details!)">
                    <button
                      onClick={() => setFeedback(prev => ({ ...prev, missing_file_viewer: !prev.missing_file_viewer }))}
                      className={`w-full p-3 rounded-lg transition-colors text-sm text-center ${feedback.missing_file_viewer
                        ? 'bg-blue-100 dark:bg-blue-900 border-2 border-blue-500 dark:border-blue-400'
                        : 'bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                        }`}
                    >
                      <div className="font-medium text-gray-900 dark:text-gray-100">Missing File Viewer</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {feedback.missing_file_viewer}
                      </div>
                    </button>
                  </Tooltip>

                  <Tooltip content="Report that this file had sensitive information in it that Nemesis didn't detect">
                    <button
                      onClick={() => setFeedback(prev => ({ ...prev, sensitive_info_not_detected: !prev.sensitive_info_not_detected }))}
                      className={`p-3 rounded-lg transition-colors text-sm text-center ${feedback.sensitive_info_not_detected
                        ? 'bg-blue-100 dark:bg-blue-900 border-2 border-blue-500 dark:border-blue-400'
                        : 'bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                        }`}
                    >
                      <div className="font-medium text-gray-900 dark:text-gray-100">Sensitive Info Not Detected</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {feedback.sensitive_info_not_detected}
                      </div>
                    </button>
                  </Tooltip>
                </div>

                <div className="h-16">
                  <div className="bg-gray-50 dark:bg-gray-800 rounded-lg transition-colors w-full h-full">
                    <div className="h-full">
                      <Editor
                        height="100%"
                        language="markdown"
                        value={editorValue}
                        onMount={handleEditorDidMount}
                        theme={isDark ? "vs-dark" : "light"}
                        options={{
                          minimap: { enabled: false },
                          scrollBeyondLastLine: false,
                          wordWrap: 'on',
                          lineNumbers: 'off',
                          folding: false,
                          fontSize: 14,
                          overviewRulerBorder: false,
                          padding: { top: 4, bottom: 4 },
                          scrollbar: {
                            vertical: 'auto',
                            horizontal: 'hidden'
                          },
                          ...(isDark && {
                            backgroundColor: { regular: '#1a1a1a' },
                            lineHighlightBackground: '#2a2a2a'
                          })
                        }}
                      />
                    </div>
                  </div>
                </div>

                <button
                  className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                  onClick={handleFeedback}
                >
                  Submit Feedback
                </button>
              </div>
            </div>

          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default FileDetailsSection;