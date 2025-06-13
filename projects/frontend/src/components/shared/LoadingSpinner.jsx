import React from 'react';

const LoadingSpinner = ({ size = 'medium', className = '' }) => {
  const sizeClasses = {
    small: 'w-4 h-4 border-2',
    medium: 'w-8 h-8 border-3',
    large: 'w-12 h-12 border-4'
  };

  return (
    <div className="flex justify-center items-center">
      <div
        className={`
          ${sizeClasses[size]}
          border-gray-300
          border-t-blue-600
          rounded-full
          animate-spin
          ${className}
        `}
      ></div>
    </div>
  );
};

// Optional Overlay Loading Spinner
export const LoadingOverlay = ({ message = 'Loading...' }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg shadow-lg text-center">
        <LoadingSpinner size="large" className="mb-4" />
        <p className="text-gray-600">{message}</p>
      </div>
    </div>
  );
};

// Optional Loading State component for empty states
export const LoadingState = ({ message = 'Loading content...' }) => {
  return (
    <div className="flex flex-col items-center justify-center p-8">
      <LoadingSpinner size="medium" className="mb-4" />
      <p className="text-gray-500">{message}</p>
    </div>
  );
};

// Optional Loading Button component
export const LoadingButton = ({
  loading,
  children,
  disabled,
  className = '',
  ...props
}) => {
  return (
    <button
      disabled={disabled || loading}
      className={`
        inline-flex items-center justify-center
        px-4 py-2 rounded
        disabled:opacity-50 disabled:cursor-not-allowed
        ${className}
      `}
      {...props}
    >
      {loading ? (
        <>
          <LoadingSpinner size="small" className="mr-2" />
          Loading...
        </>
      ) : children}
    </button>
  );
};

export default LoadingSpinner;