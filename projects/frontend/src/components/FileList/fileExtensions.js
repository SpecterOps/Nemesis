// used for file filtering

export const CONFIG_FILE_EXTENSIONS = [
    // General Configuration
    'yaml',    // YAML
    'yml',     // YAML alternative
    'json',    // JSON
    'json5',   // JSON5 (JSON with comments)
    'toml',    // TOML
    'ini',     // INI
    'conf',    // Generic config
    'config',  // Generic config
    'cfg',     // Generic config
    'env',     // Environment variables
    'properties', // Java properties
  
    // Build Systems & Package Management
    'xml',     // XML (Maven, Ant)
    'pom',     // Maven POM
    'gradle',  // Gradle
    'lock',    // Lock files (yarn.lock, Gemfile.lock)
    'dockerfile', // Docker
    'npmrc',   // NPM config
    'yarnrc',  // Yarn config
    'babelrc', // Babel config
    'eslintrc',// ESLint config
    'prettierrc', // Prettier config
    'stylelintrc', // Stylelint config
    'editorconfig', // Editor config
    
    // CI/CD & Deployment
    'travis.yml',    // Travis CI
    'gitlab-ci.yml', // GitLab CI
    'jenkins',       // Jenkins
    'circleci',      // Circle CI
    'github',        // GitHub Actions
    'azure-pipelines.yml', // Azure Pipelines
    
    // Infrastructure & Cloud
    'tf',      // Terraform
    'tfvars',  // Terraform variables
    'hcl',     // HashiCorp Configuration Language
    'nomad',   // Nomad job files
    'consul',  // Consul config
    'vault',   // Vault config
    'k8s',     // Kubernetes
    'helm',    // Helm charts
    'cloudformation', // AWS CloudFormation
    'arm',     // Azure ARM templates
  
    // Web Servers
    'htaccess',   // Apache
    'nginx',      // Nginx
    'apache2',    // Apache2
    'vhost',      // Virtual hosts
  
    // Security & Auth
    'cert',    // Certificates
    'crt',     // Certificates
    'key',     // Keys
    'pem',     // Privacy Enhanced Mail
    'csr',     // Certificate Signing Requests
    'pub',     // Public keys
  
    // Project-specific
    'rc',          // Generic runtime config
    'gitignore',   // Git ignore rules
    'gitattributes', // Git attributes
    'browserslistrc', // Browserslist
    'npmignore',   // NPM ignore rules
    'dockerignore', // Docker ignore rules
    'gcloudignore', // Google Cloud ignore rules
    'jshintrc',    // JSHint
    'csslintrc',   // CSS Lint
    'modernizrrc',  // Modernizr
    'bowerrc',     // Bower
    'postcssrc',   // PostCSS
    'sassrc',      // Sass
    'babel',       // Babel
    'webpack',     // Webpack
    'rollup',      // Rollup
    'viterc',      // Vite
    'swcrc',       // SWC
    'tsconfig',    // TypeScript
    'pyproject',   // Python project
    'requirements.txt', // Python requirements
    'gemspec',     // Ruby gems
    'rubocop',     // RuboCop
    'rspec',       // RSpec
    'cargo',       // Rust Cargo
    'maven',       // Maven
    'sbt',         // Scala SBT
    'ivy',         // Ivy
    'nuget',       // NuGet
    'composer',    // Composer (PHP)
    'phpunit',     // PHPUnit
];

export const SOURCE_CODE_EXTENSIONS = [
    // Web/JavaScript ecosystem
    'js',      // JavaScript
    'jsx',     // React
    'ts',      // TypeScript
    'tsx',     // TypeScript React
    'vue',     // Vue
    'svelte',  // Svelte
    'html',    // HTML
    'css',     // CSS
    'scss',    // SASS
    'less',    // LESS
    'json',    // JSON
    'xml',     // XML
    'wasm',    // WebAssembly
  
    // Systems Programming
    'c',       // C
    'h',       // C header
    'cpp',     // C++
    'hpp',     // C++ header
    'cc',      // C++
    'cxx',     // C++
    'rs',      // Rust
    'go',      // Go
    'asm',     // Assembly
    's',       // Assembly
  
    // JVM Languages
    'java',    // Java
    'class',   // Java bytecode
    'jar',     // Java archive
    'scala',   // Scala
    'kt',      // Kotlin
    'groovy',  // Groovy
    'clj',     // Clojure
  
    // Microsoft/.NET
    'cs',      // C#
    'vb',      // Visual Basic
    'fs',      // F#
    'fsx',     // F# script
    'xaml',    // XAML
  
    // Scripting Languages
    'py',      // Python
    'pyc',     // Python compiled
    'rb',      // Ruby
    'erb',     // Ruby templates
    'php',     // PHP
    'pl',      // Perl
    'pm',      // Perl module
    't',       // Perl test
    'sh',      // Shell
    'bash',    // Bash
    'zsh',     // Zsh
    'fish',    // Fish
    'lua',     // Lua
    'tcl',     // Tcl
  
    // Mobile Development
    'swift',   // Swift
    'm',       // Objective-C
    'mm',      // Objective-C++
    'h',       // Objective-C header
    'kotlin',  // Kotlin
    'dart',    // Dart/Flutter
  
    // Data Science/Statistical
    'r',       // R
    'rmd',     // R Markdown
    'jl',      // Julia
    'matlab',  // MATLAB
    'octave',  // Octave
    'ipynb',   // Jupyter notebook
  
    // Database
    'sql',     // SQL
    'psql',    // PostgreSQL
    'plsql',   // PL/SQL
    'mysql',   // MySQL
  
    // Build
    'cmake',   // CMake
    'make',    // Makefile
    
    // Functional Programming
    'hs',      // Haskell
    'lhs',     // Literate Haskell
    'elm',     // Elm
    'ml',      // OCaml
    'mli',     // OCaml interface
    'erl',     // Erlang
    'ex',      // Elixir
    'exs',     // Elixir script
    'eex',     // Elixir template
    'lisp',    // Lisp
    'scm',     // Scheme
    'rkt',     // Racket
  
    // Other
    'd',       // D
    'nim',     // Nim
    'cr',      // Crystal
    'zig',     // Zig
    'v',       // V
    'ada',     // Ada
    'f90',     // Fortran
    'f95',     // Fortran
    'f03',     // Fortran
    'cob',     // COBOL
    'proto',   // Protocol Buffers
    'gradle',  // Gradle
    'pas',     // Pascal
    'dpr',     // Delphi
];

export const OFFICE_EXTENSIONS = [
    'doc',     // Word Document
    'docx',    // Word Document (Modern)
    'xls',     // Excel Spreadsheet
    'xlsx',    // Excel Spreadsheet (Modern)
    'ppt',     // PowerPoint Presentation
    'pptx',    // PowerPoint Presentation (Modern)
];