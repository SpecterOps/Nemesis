import React from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism';
import remarkGfm from 'remark-gfm';

// Custom light theme with darker background
const customLightTheme = {
  ...oneLight,
  'code[class*="language-"]': {
    ...oneLight['code[class*="language-"]'],
    background: '#A0A0A0', // Slightly darker background (gray-100)
  },
  'pre[class*="language-"]': {
    ...oneLight['pre[class*="language-"]'],
    background: '#A0A0A0', // Slightly darker background (gray-100)
  },
  ':not(pre) > code[class*="language-"]': {
    ...oneLight[':not(pre) > code[class*="language-"]'],
    background: '#A0A0A0', // Slightly darker background (gray-100)
  },
};

const customDarkTheme = {
  'code[class*="language-"]': {
    color: '#c5c8c6',
    textShadow: '0 1px rgba(0, 0, 0, 0.3)',
    fontFamily: 'Inconsolata, Monaco, Consolas, "Courier New", Courier, monospace',
    direction: 'ltr',
    textAlign: 'left',
    whiteSpace: 'pre',
    wordSpacing: 'normal',
    wordBreak: 'normal',
    lineHeight: '1.5',
    MozTabSize: '4',
    OTabSize: '4',
    tabSize: '4',
    WebkitHyphens: 'none',
    MozHyphens: 'none',
    msHyphens: 'none',
    hyphens: 'none',
  },
  'pre[class*="language-"]': {
    color: '#c5c8c6',
    textShadow: '0 1px rgba(0, 0, 0, 0.3)',
    fontFamily: 'Inconsolata, Monaco, Consolas, "Courier New", Courier, monospace',
    direction: 'ltr',
    textAlign: 'left',
    whiteSpace: 'pre',
    wordSpacing: 'normal',
    wordBreak: 'normal',
    lineHeight: '1.5',
    MozTabSize: '4',
    OTabSize: '4',
    tabSize: '4',
    WebkitHyphens: 'none',
    MozHyphens: 'none',
    msHyphens: 'none',
    hyphens: 'none',
    padding: '1em',
    margin: '.5em 0',
    overflow: 'auto',
    borderRadius: '0.3em',
    background: '#2d3343',
  },
  ':not(pre) > code[class*="language-"]': {
    background: '#2d3343',
    padding: '.1em',
    borderRadius: '.3em',
  },
  comment: { color: '#7C7C7C' },
  prolog: { color: '#7C7C7C' },
  doctype: { color: '#7C7C7C' },
  cdata: { color: '#7C7C7C' },
  punctuation: { color: '#c5c8c6' },
  '.namespace': { opacity: '.7' },
  property: { color: '#96CBFE' },
  keyword: { color: '#96CBFE' },
  tag: { color: '#96CBFE' },
  'class-name': {
    color: '#FFFFB6',
    textDecoration: 'underline',
  },
  boolean: { color: '#99CC99' },
  constant: { color: '#99CC99' },
  symbol: { color: '#f92672' },
  deleted: { color: '#f92672' },
  number: { color: '#FF73FD' },
  selector: { color: '#A8FF60' },
  'attr-name': { color: '#A8FF60' },
  string: { color: '#A8FF60' },
  char: { color: '#A8FF60' },
  builtin: { color: '#A8FF60' },
  inserted: { color: '#A8FF60' },
  variable: { color: '#C6C5FE' },
  operator: { color: '#EDEDED' },
  entity: {
    color: '#FFFFB6',
    cursor: 'help',
  },
  url: { color: '#96CBFE' },
  '.language-css .token.string': { color: '#87C38A' },
  '.style .token.string': { color: '#87C38A' },
  atrule: { color: '#F9EE98' },
  'attr-value': { color: '#F9EE98' },
  function: { color: '#DAD085' },
  regex: { color: '#E9C062' },
  important: {
    color: '#fd971f',
    fontWeight: 'bold',
  },
  bold: { fontWeight: 'bold' },
  italic: { fontStyle: 'italic' },
};

const MarkdownRenderer = ({ content }) => {
  const isDarkMode = document.documentElement.classList.contains('dark');

  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        // Headings
        h1: ({ node, ...props }) => (
          <h1 {...props} className="text-2xl font-bold dark:text-gray-100 mb-6 pb-2 border-b border-gray-200 dark:border-gray-700" />
        ),
        h2: ({ node, ...props }) => (
          <h2 {...props} className="text-xl font-bold dark:text-gray-100 mb-4 mt-6" />
        ),
        h3: ({ node, ...props }) => (
          <h3 {...props} className="text-lg font-semibold dark:text-gray-100 mb-3 mt-4" />
        ),
        h4: ({ node, ...props }) => (
          <h4 {...props} className="text-base font-medium dark:text-gray-100 mb-2 mt-3" />
        ),

        // Lists with reduced spacing
        ul: ({ node, ...props }) => (
          <ul {...props} className="mb-2" />
        ),
        ol: ({ node, ...props }) => (
          <ol {...props} className="mb-2" />
        ),
        li: ({ node, ...props }) => (
          <li {...props} className="text-gray-700 dark:text-gray-300 flex items-baseline mb-1">
            <span className="inline-block w-3 mr-1">•</span>
            <span className="flex-1">{props.children}</span>
          </li>
        ),

        // Block elements
        p: ({ node, ...props }) => (
          <p {...props} className="text-gray-700 dark:text-gray-300 mb-4 leading-relaxed" />
        ),
        blockquote: ({ node, ...props }) => (
          <blockquote {...props} className="border-l-4 border-gray-200 dark:border-gray-700 pl-4 py-2 mb-4 italic" />
        ),

        // Table elements
        table: ({ node, ...props }) => (
          <div className="overflow-x-auto mb-6">
            <table {...props} className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 border border-gray-200 dark:border-gray-700 rounded-lg" />
          </div>
        ),
        thead: ({ node, ...props }) => (
          <thead {...props} className="bg-gray-50 dark:bg-gray-800" />
        ),
        tbody: ({ node, ...props }) => (
          <tbody {...props} className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700" />
        ),
        tr: ({ node, ...props }) => (
          <tr {...props} className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors" />
        ),
        th: ({ node, ...props }) => (
          <th {...props} className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider" />
        ),
        td: ({ node, ...props }) => (
          <td {...props} className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400" />
        ),

        // Inline elements
        a: ({ node, ...props }) => (
          <a {...props} className="text-blue-600 dark:text-blue-400 hover:underline" />
        ),
        strong: ({ node, ...props }) => (
          <strong {...props} className="font-bold text-gray-900 dark:text-gray-100" />
        ),
        em: ({ node, ...props }) => (
          <em {...props} className="italic text-gray-900 dark:text-gray-100" />
        ),

        // Code blocks with consistent styling
        code: ({ node, inline, className, children, ...props }) => {
          const match = /language-(\w+)/.exec(className || '');
          const language = match ? match[1] : 'text';

          return !inline && className ? (
            <SyntaxHighlighter
              language={language}
              style={isDarkMode ? customDarkTheme : customLightTheme}
              customStyle={{
                margin: '0 0 0 0',
                borderRadius: '0.5rem',
                padding: '1rem',
                background: isDarkMode ? 'rgb(55, 65, 81)' // equivalent to dark:bg-gray-700
                  : 'rgb(249, 250, 251)' // equivalent to bg-gray-50
              }}
              {...props}
            >
              {String(children).replace(/\n$/, '')}
            </SyntaxHighlighter>
          ) : (
            <span className="inline-flex items-center">
              <code
                className="px-1.5 mb-0 pb-0 py-0.5 text-sm bg-gray-300 dark:bg-gray-500 rounded font-mono"
                {...props}
              >
                {children}
              </code>
            </span>
          );
        },

        pre: ({ node, ...props }) => (
          <pre {...props} className="mb-4 overflow-x-auto" />
        ),
        hr: ({ node, ...props }) => (
          <hr {...props} className="my-8 border-t border-gray-200 dark:border-gray-700" />
        )
      }}
    >
      {content}
    </ReactMarkdown>
  );
};

export default MarkdownRenderer;