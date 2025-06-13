import React, { useState } from 'react';
import { Tooltip as TooltipPrimitive } from '@radix-ui/react-tooltip';

const Tooltip = ({
  children,
  content,
  side = 'top',
  align = 'center',
  className = '',
  maxWidth = '300px'
}) => {
  const [open, setOpen] = useState(false);

  return (
    <TooltipPrimitive.Provider>
      <TooltipPrimitive.Root open={open} onOpenChange={setOpen}>
        <TooltipPrimitive.Trigger asChild>
          <div
            onMouseEnter={() => setOpen(true)}
            onMouseLeave={() => setOpen(false)}
            onClick={() => setOpen(!open)} // Toggle on click for mobile support
          >
            {children}
          </div>
        </TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content
            side={side}
            align={align}
            sideOffset={4}
            className={`z-50 overflow-hidden rounded-md bg-gray-900 dark:bg-gray-200 px-3 py-2 text-sm text-white dark:text-gray-900 shadow-md animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 ${className}`}
            style={{ maxWidth }}
          >
            <div className="break-words">
              {content}
            </div>
            <TooltipPrimitive.Arrow className="fill-gray-900 dark:fill-gray-200" />
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
};

export default Tooltip;