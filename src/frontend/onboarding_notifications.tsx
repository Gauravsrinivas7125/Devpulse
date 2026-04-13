/**
 * DevPulse - Onboarding Wizard & In-App Notifications
 * Complete user onboarding and notification system
 */

import React, { useState, useEffect, useCallback } from 'react';
import AuthService from './auth-service';

// ============================================================================
// TYPES
// ============================================================================

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  action: string;
  estimatedTime: string;
  completed: boolean;
  skipped: boolean;
}

interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: Date;
  autoClose?: boolean;
  duration?: number;
}

// ============================================================================
// ONBOARDING WIZARD
// ============================================================================

export const OnboardingWizard: React.FC<{
  onComplete: () => void;
  onSkip: () => void;
}> = ({ onComplete, onSkip }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [steps, setSteps] = useState<OnboardingStep[]>([
    {
      id: 'import',
      title: '📥 Import Your First API Collection',
      description: 'Upload a Postman collection or create manually',
      action: 'import_collection',
      estimatedTime: '5 minutes',
      completed: false,
      skipped: false,
    },
    {
      id: 'scan',
      title: '🔍 Run Your First Security Scan',
      description: 'Scan your APIs for vulnerabilities',
      action: 'run_scan',
      estimatedTime: '2 minutes',
      completed: false,
      skipped: false,
    },
    {
      id: 'review',
      title: '📋 Review Security Findings',
      description: 'Understand and fix security issues',
      action: 'review_findings',
      estimatedTime: '10 minutes',
      completed: false,
      skipped: false,
    },
    {
      id: 'team',
      title: '👥 Invite Team Members',
      description: 'Add your team to collaborate',
      action: 'invite_members',
      estimatedTime: '5 minutes',
      completed: false,
      skipped: false,
    },
    {
      id: 'compliance',
      title: '✅ Setup Compliance Reporting',
      description: 'Generate compliance reports',
      action: 'setup_compliance',
      estimatedTime: '5 minutes',
      completed: false,
      skipped: false,
    },
  ]);

  const step = steps[currentStep];
  const progress = ((currentStep + 1) / steps.length) * 100;

  const handleNext = useCallback(async () => {
    const newSteps = [...steps];
    newSteps[currentStep].completed = true;
    setSteps(newSteps);

    // Wire step actions to backend APIs
    const token = AuthService.getToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

    try {
      if (step.id === 'import') {
        // Create workspace on the first step
        await fetch(`${API_URL}/api/workspaces/create`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ name: 'My Workspace' }),
        });
      }

      if (currentStep === steps.length - 1) {
        // Mark onboarding complete on last step
        await fetch(`${API_URL}/api/onboarding/complete`, {
          method: 'POST',
          headers,
        });
        onComplete();
      } else {
        setCurrentStep(currentStep + 1);
      }
    } catch (err) {
      console.error('Onboarding step error:', err);
      // Still advance even if API call fails
      if (currentStep < steps.length - 1) {
        setCurrentStep(currentStep + 1);
      } else {
        onComplete();
      }
    }
  }, [currentStep, steps, step, onComplete]);

  const handleSkip = () => {
    const newSteps = [...steps];
    newSteps[currentStep].skipped = true;
    setSteps(newSteps);

    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      onSkip();
    }
  };

  const handleSkipAll = () => {
    onSkip();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-2xl max-w-2xl w-full mx-4">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-8 py-6 text-white rounded-t-lg">
          <div className="flex justify-between items-center mb-4">
            <h1 className="text-3xl font-bold">Welcome to DevPulse! 🚀</h1>
            <button
              onClick={handleSkipAll}
              className="text-white hover:text-blue-100 text-sm"
            >
              Skip All
            </button>
          </div>
          <div className="w-full bg-blue-500 rounded-full h-2">
            <div
              className="bg-white h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-blue-100 text-sm mt-2">
            Step {currentStep + 1} of {steps.length}
          </p>
        </div>

        {/* Content */}
        <div className="px-8 py-6">
          <div className="mb-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-2">{step.title}</h2>
            <p className="text-gray-600 text-lg">{step.description}</p>
            <p className="text-gray-500 text-sm mt-2">⏱️ Estimated time: {step.estimatedTime}</p>
          </div>

          {/* Step Content */}
          <div className="bg-gray-50 rounded-lg p-6 mb-6">
            {step.id === 'import' && (
              <div>
                <p className="text-gray-700 mb-4">
                  Upload your Postman collection to get started with security scanning.
                </p>
                <button className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700">
                  📤 Upload Collection
                </button>
              </div>
            )}
            {step.id === 'scan' && (
              <div>
                <p className="text-gray-700 mb-4">
                  Run a comprehensive security scan on your APIs to identify vulnerabilities.
                </p>
                <button className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700">
                  🔍 Start Scan
                </button>
              </div>
            )}
            {step.id === 'review' && (
              <div>
                <p className="text-gray-700 mb-4">
                  Review the security findings and understand how to fix them.
                </p>
                <button className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700">
                  📊 View Findings
                </button>
              </div>
            )}
            {step.id === 'team' && (
              <div>
                <p className="text-gray-700 mb-4">
                  Invite your team members to collaborate on security improvements.
                </p>
                <button className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700">
                  👥 Invite Team
                </button>
              </div>
            )}
            {step.id === 'compliance' && (
              <div>
                <p className="text-gray-700 mb-4">
                  Setup automated compliance reporting for your organization.
                </p>
                <button className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700">
                  ✅ Setup Compliance
                </button>
              </div>
            )}
          </div>

          {/* Completed Steps */}
          {steps.filter((s) => s.completed).length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Completed Steps</h3>
              <div className="space-y-2">
                {steps
                  .filter((s) => s.completed)
                  .map((s) => (
                    <div key={s.id} className="flex items-center text-green-600">
                      <span className="text-xl mr-2">✓</span>
                      <span>{s.title}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-gray-50 px-8 py-4 rounded-b-lg flex justify-between">
          <button
            onClick={handleSkip}
            className="text-gray-600 hover:text-gray-900 font-medium"
          >
            Skip This Step
          </button>
          <button
            onClick={handleNext}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 font-medium"
          >
            {currentStep === steps.length - 1 ? 'Complete' : 'Next'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// NOTIFICATION SYSTEM
// ============================================================================

export const NotificationContainer: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  // Global notification handler
  useEffect(() => {
    const handleNotification = (event: CustomEvent) => {
      const notification: Notification = {
        id: `notif_${Date.now()}`,
        timestamp: new Date(),
        autoClose: true,
        duration: 5000,
        ...event.detail,
      };

      setNotifications((prev) => [...prev, notification]);

      if (notification.autoClose && notification.duration) {
        setTimeout(() => {
          removeNotification(notification.id);
        }, notification.duration);
      }
    };

    window.addEventListener('devpulse:notification', handleNotification as EventListener);
    return () => {
      window.removeEventListener('devpulse:notification', handleNotification as EventListener);
    };
  }, []);

  const removeNotification = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  return (
    <div className="fixed top-4 right-4 space-y-3 z-40 max-w-md">
      {notifications.map((notification) => (
        <NotificationItem
          key={notification.id}
          notification={notification}
          onClose={() => removeNotification(notification.id)}
        />
      ))}
    </div>
  );
};

interface NotificationItemProps {
  notification: Notification;
  onClose: () => void;
}

const NotificationItem: React.FC<NotificationItemProps> = ({ notification, onClose }) => {
  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  };

  const colors = {
    success: 'bg-green-50 border-green-200 text-green-800',
    error: 'bg-red-50 border-red-200 text-red-800',
    warning: 'bg-yellow-50 border-yellow-200 text-yellow-800',
    info: 'bg-blue-50 border-blue-200 text-blue-800',
  };

  return (
    <div
      className={`border rounded-lg p-4 shadow-lg flex items-start space-x-3 ${colors[notification.type]}`}
    >
      <span className="text-xl flex-shrink-0">{icons[notification.type]}</span>
      <div className="flex-1">
        <h3 className="font-semibold">{notification.title}</h3>
        <p className="text-sm opacity-90">{notification.message}</p>
      </div>
      <button
        onClick={onClose}
        className="text-lg hover:opacity-70 flex-shrink-0"
      >
        ✕
      </button>
    </div>
  );
};

// ============================================================================
// NOTIFICATION HELPER
// ============================================================================

export const showNotification = (
  type: 'success' | 'error' | 'warning' | 'info',
  title: string,
  message: string,
  duration?: number
) => {
  const event = new CustomEvent('devpulse:notification', {
    detail: {
      type,
      title,
      message,
      duration: duration || 5000,
    },
  });
  window.dispatchEvent(event);
};

// ============================================================================
// EXPORT
// ============================================================================

export default {
  OnboardingWizard,
  NotificationContainer,
  showNotification,
};
