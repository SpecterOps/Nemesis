import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import React from 'react';

const Tooltip = ({
  children,
  content,
  delayDuration = 50,
  sideOffset = 5,
  side = 'right',
  align = 'center',
  maxWidth = 'xs',
  ...props
}) => {
  if (!content) {
    return children;
  }

  const maxWidthClasses = {
    xs: 'max-w-xs',
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
    '2xl': 'max-w-2xl',
    full: 'max-w-full'
  };

  return (
    <TooltipPrimitive.Provider>
      <TooltipPrimitive.Root delayDuration={delayDuration}>
        <TooltipPrimitive.Trigger asChild>
          {children}
        </TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content
            sideOffset={sideOffset}
            side={side}
            align={align}
            className={`${maxWidthClasses[maxWidth] || 'max-w-xs'} bg-gray-800 dark:bg-gray-100 text-white dark:text-gray-900 px-3 py-2 rounded-md text-sm shadow-lg animate-in fade-in-0 zoom-in-95 duration-100`}
            {...props}
          >
            {content}
            <TooltipPrimitive.Arrow className="fill-gray-800 dark:fill-gray-100" />
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
};

export default Tooltip;