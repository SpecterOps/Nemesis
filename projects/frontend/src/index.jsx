import React from 'react';
import ReactDOM from 'react-dom/client';
import loader from '@monaco-editor/loader';
import * as monaco from 'monaco-editor';
import App from './App';
import './index.css';

loader.config({ monaco });

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);