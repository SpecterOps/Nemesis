const Alert = ({ title, children, variant = "error" }) => (
  <div className={`p-4 rounded-lg flex items-center space-x-2 ${variant === "error"
    ? "bg-red-50 dark:bg-red-900/20"
    : "bg-blue-50 dark:bg-blue-900/20"
    }`}>
    <AlertTriangle className={`w-5 h-5 ${variant === "error"
      ? "text-red-500 dark:text-red-400"
      : "text-blue-500 dark:text-blue-400"
      }`} />
    <div className="flex flex-col">
      <span className={`font-medium ${variant === "error"
        ? "text-red-800 dark:text-red-400"
        : "text-blue-800 dark:text-blue-400"
        }`}>
        {title}
      </span>
      <span className={`text-sm ${variant === "error"
        ? "text-red-600 dark:text-red-300"
        : "text-blue-600 dark:text-blue-300"
        }`}>
        {children}
      </span>
    </div>
  </div>
);

export default Alert;