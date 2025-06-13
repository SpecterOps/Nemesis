import React, { useEffect, useRef, useState } from 'react';

const Tooltip = ({ children, content }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [position, setPosition] = useState('right');
  const tooltipRef = useRef(null);
  const containerRef = useRef(null);

  const calculatePosition = () => {
    if (!tooltipRef.current || !containerRef.current) return;

    const tooltip = tooltipRef.current.getBoundingClientRect();
    const container = containerRef.current.getBoundingClientRect();
    const viewport = {
      width: window.innerWidth,
      height: window.innerHeight
    };

    // Check if there's enough space in each direction
    const spaceAbove = container.top;
    const spaceBelow = viewport.height - container.bottom;
    const spaceLeft = container.left;
    const spaceRight = viewport.width - container.right;

    // Find the direction with most space, with preference for right position
    const spaces = [
      { direction: 'right', space: spaceRight * 1.5 }, // Prioritize right position
      { direction: 'left', space: spaceLeft },
      { direction: 'top', space: spaceAbove },
      { direction: 'bottom', space: spaceBelow }
    ];

    const bestPosition = spaces.reduce((prev, current) =>
      current.space > prev.space ? current : prev
    );

    setPosition(bestPosition.direction);
  };

  useEffect(() => {
    if (isVisible) {
      calculatePosition();
      window.addEventListener('resize', calculatePosition);
      return () => window.removeEventListener('resize', calculatePosition);
    }
  }, [isVisible]);

  const getTooltipStyles = () => {
    // Enhanced base styles with larger text and stronger background
    const baseStyles = "z-[100] text-sm font-medium text-white bg-gray-600 absolute min-w-[140px] max-w-[320px] w-fit whitespace-normal shadow-lg border border-gray-700";

    // Larger notch with matching background
    const notchBaseStyles = "absolute bg-gray-600 w-3 h-3 rotate-45 border border-gray-700";

    switch (position) {
      case 'right':
        return {
          tooltip: `${baseStyles} top-1/2 left-full ml-3 transform -translate-y-1/2 rounded-lg`,
          notch: `${notchBaseStyles} left-0 top-1/2 -translate-x-1/2 -translate-y-1/2`
        };
      case 'left':
        return {
          tooltip: `${baseStyles} top-1/2 right-full mr-3 transform -translate-y-1/2 rounded-lg`,
          notch: `${notchBaseStyles} right-0 top-1/2 translate-x-1/2 -translate-y-1/2`
        };
      case 'top':
        return {
          tooltip: `${baseStyles} -top-2 left-1/2 transform -translate-x-1/2 -translate-y-full rounded-lg`,
          notch: `${notchBaseStyles} bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2`
        };
      case 'bottom':
        return {
          tooltip: `${baseStyles} top-full mt-3 left-1/2 transform -translate-x-1/2 rounded-lg`,
          notch: `${notchBaseStyles} top-0 left-1/2 -translate-x-1/2 -translate-y-1/2`
        };
      default:
        return {
          tooltip: `${baseStyles} top-1/2 left-full ml-3 transform -translate-y-1/2 rounded-lg`,
          notch: `${notchBaseStyles} left-0 top-1/2 -translate-x-1/2 -translate-y-1/2`
        };
    }
  };

  return (
    <div
      className="relative inline-block"
      ref={containerRef}
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
    >
      {children}
      {isVisible && (
        <div
          ref={tooltipRef}
          className={getTooltipStyles().tooltip}
        >
          <div className="relative px-4 py-2">
            {content}
            <div className={getTooltipStyles().notch} />
          </div>
        </div>
      )}
    </div>
  );
};

export default Tooltip;