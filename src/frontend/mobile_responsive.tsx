/**
 * DevPulse - Mobile Responsive UI
 * Zeno-based responsive design for all screen sizes
 */

import React, { useState, useEffect } from 'react';

// ============================================================================
// RESPONSIVE BREAKPOINTS
// ============================================================================

const BREAKPOINTS = {
  mobile: 480,
  tablet: 768,
  desktop: 1024,
  wide: 1440,
};

type ScreenSize = 'mobile' | 'tablet' | 'desktop' | 'wide';

// ============================================================================
// HOOKS
// ============================================================================

/**
 * Hook to detect current screen size
 */
export const useResponsive = (): ScreenSize => {
  const [screenSize, setScreenSize] = useState<ScreenSize>('desktop');

  useEffect(() => {
    const handleResize = () => {
      const width = window.innerWidth;
      
      if (width < BREAKPOINTS.mobile) {
        setScreenSize('mobile');
      } else if (width < BREAKPOINTS.tablet) {
        setScreenSize('mobile');
      } else if (width < BREAKPOINTS.desktop) {
        setScreenSize('tablet');
      } else if (width < BREAKPOINTS.wide) {
        setScreenSize('desktop');
      } else {
        setScreenSize('wide');
      }
    };

    window.addEventListener('resize', handleResize);
    handleResize(); // Call once on mount

    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return screenSize;
};

/**
 * Hook to check if screen is mobile
 */
export const useIsMobile = (): boolean => {
  const screenSize = useResponsive();
  return screenSize === 'mobile';
};

/**
 * Hook to check if screen is tablet or smaller
 */
export const useIsTabletOrSmaller = (): boolean => {
  const screenSize = useResponsive();
  return screenSize === 'mobile' || screenSize === 'tablet';
};

// ============================================================================
// RESPONSIVE COMPONENTS
// ============================================================================

/**
 * Responsive Container
 */
export const ResponsiveContainer: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const screenSize = useResponsive();

  const containerStyles = {
    mobile: 'px-4 py-2',
    tablet: 'px-6 py-4',
    desktop: 'px-8 py-6',
    wide: 'px-12 py-8 max-w-7xl mx-auto',
  };

  return (
    <div className={containerStyles[screenSize]}>
      {children}
    </div>
  );
};

/**
 * Responsive Grid
 */
interface ResponsiveGridProps {
  children: React.ReactNode;
  columns?: number;
}

export const ResponsiveGrid: React.FC<ResponsiveGridProps> = ({ children, columns = 3 }) => {
  const screenSize = useResponsive();

  const gridClasses = {
    mobile: 'grid-cols-1',
    tablet: 'grid-cols-2',
    desktop: `grid-cols-${columns}`,
    wide: `grid-cols-${columns + 1}`,
  };

  return (
    <div className={`grid gap-4 ${gridClasses[screenSize]}`}>
      {children}
    </div>
  );
};

/**
 * Responsive Navigation
 */
interface NavItem {
  label: string;
  href: string;
  icon?: React.ReactNode;
}

interface ResponsiveNavProps {
  items: NavItem[];
  logo?: React.ReactNode;
}

export const ResponsiveNav: React.FC<ResponsiveNavProps> = ({ items, logo }) => {
  const [isOpen, setIsOpen] = useState(false);
  const isMobile = useIsMobile();

  if (isMobile) {
    return (
      <nav className="bg-white shadow-md">
        <div className="flex justify-between items-center px-4 py-3">
          <div className="flex-shrink-0">{logo}</div>
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="text-gray-600 hover:text-gray-900"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>
        {isOpen && (
          <div className="px-2 pt-2 pb-3 space-y-1">
            {items.map((item) => (
              <a
                key={item.href}
                href={item.href}
                className="block px-3 py-2 rounded-md text-base font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50"
              >
                {item.icon && <span className="mr-2">{item.icon}</span>}
                {item.label}
              </a>
            ))}
          </div>
        )}
      </nav>
    );
  }

  return (
    <nav className="bg-white shadow-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">{logo}</div>
          <div className="flex items-center space-x-4">
            {items.map((item) => (
              <a
                key={item.href}
                href={item.href}
                className="text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
              >
                {item.icon && <span className="mr-2">{item.icon}</span>}
                {item.label}
              </a>
            ))}
          </div>
        </div>
      </div>
    </nav>
  );
};

/**
 * Responsive Card
 */
interface ResponsiveCardProps {
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export const ResponsiveCard: React.FC<ResponsiveCardProps> = ({ title, children, footer }) => {
  const screenSize = useResponsive();

  const cardPadding = {
    mobile: 'p-3',
    tablet: 'p-4',
    desktop: 'p-6',
    wide: 'p-8',
  };

  return (
    <div className={`bg-white rounded-lg shadow-md ${cardPadding[screenSize]}`}>
      <h3 className="text-lg font-semibold mb-4">{title}</h3>
      <div>{children}</div>
      {footer && <div className="mt-4 pt-4 border-t">{footer}</div>}
    </div>
  );
};

/**
 * Responsive Table
 */
interface ResponsiveTableProps {
  headers: string[];
  rows: (string | React.ReactNode)[][];
}

export const ResponsiveTable: React.FC<ResponsiveTableProps> = ({ headers, rows }) => {
  const isMobile = useIsMobile();

  if (isMobile) {
    return (
      <div className="space-y-4">
        {rows.map((row, rowIndex) => (
          <div key={rowIndex} className="bg-white rounded-lg shadow-md p-4">
            {headers.map((header, colIndex) => (
              <div key={colIndex} className="flex justify-between py-2">
                <span className="font-semibold text-gray-700">{header}</span>
                <span className="text-gray-600">{row[colIndex]}</span>
              </div>
            ))}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="bg-gray-100">
            {headers.map((header, index) => (
              <th key={index} className="border px-4 py-2 text-left font-semibold">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={rowIndex} className="border-b hover:bg-gray-50">
              {row.map((cell, colIndex) => (
                <td key={colIndex} className="border px-4 py-2">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

/**
 * Responsive Modal
 */
interface ResponsiveModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export const ResponsiveModal: React.FC<ResponsiveModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  footer,
}) => {
  const screenSize = useResponsive();

  if (!isOpen) return null;

  const modalWidth = {
    mobile: 'w-full h-full',
    tablet: 'w-11/12 max-h-screen',
    desktop: 'w-2/3 max-h-screen',
    wide: 'w-1/2 max-h-screen',
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className={`bg-white rounded-lg shadow-lg ${modalWidth[screenSize]} overflow-auto`}>
        <div className="flex justify-between items-center p-6 border-b">
          <h2 className="text-2xl font-bold">{title}</h2>
          <button
            onClick={onClose}
            className="text-gray-600 hover:text-gray-900"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6">{children}</div>
        {footer && <div className="p-6 border-t flex justify-end space-x-4">{footer}</div>}
      </div>
    </div>
  );
};

/**
 * Responsive Form
 */
interface FormField {
  name: string;
  label: string;
  type: 'text' | 'email' | 'password' | 'textarea' | 'select';
  required?: boolean;
  options?: { label: string; value: string }[];
}

interface ResponsiveFormProps {
  fields: FormField[];
  onSubmit: (data: Record<string, string>) => void;
  submitLabel?: string;
}

export const ResponsiveForm: React.FC<ResponsiveFormProps> = ({
  fields,
  onSubmit,
  submitLabel = 'Submit',
}) => {
  const [formData, setFormData] = useState<Record<string, string>>({});
  const screenSize = useResponsive();

  const inputClasses = {
    mobile: 'w-full px-3 py-2 text-sm',
    tablet: 'w-full px-4 py-2 text-base',
    desktop: 'w-full px-4 py-3 text-base',
    wide: 'w-full px-4 py-3 text-base',
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {fields.map((field) => (
        <div key={field.name}>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            {field.label}
            {field.required && <span className="text-red-500">*</span>}
          </label>
          {field.type === 'textarea' ? (
            <textarea
              name={field.name}
              value={formData[field.name] || ''}
              onChange={handleChange}
              required={field.required}
              className={`${inputClasses[screenSize]} border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500`}
              rows={4}
            />
          ) : field.type === 'select' ? (
            <select
              name={field.name}
              value={formData[field.name] || ''}
              onChange={handleChange}
              required={field.required}
              className={`${inputClasses[screenSize]} border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500`}
            >
              <option value="">Select {field.label}</option>
              {field.options?.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          ) : (
            <input
              type={field.type}
              name={field.name}
              value={formData[field.name] || ''}
              onChange={handleChange}
              required={field.required}
              className={`${inputClasses[screenSize]} border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500`}
            />
          )}
        </div>
      ))}
      <button
        type="submit"
        className="w-full bg-blue-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
      >
        {submitLabel}
      </button>
    </form>
  );
};

// ============================================================================
// EXPORT
// ============================================================================

export default {
  useResponsive,
  useIsMobile,
  useIsTabletOrSmaller,
  ResponsiveContainer,
  ResponsiveGrid,
  ResponsiveNav,
  ResponsiveCard,
  ResponsiveTable,
  ResponsiveModal,
  ResponsiveForm,
};
