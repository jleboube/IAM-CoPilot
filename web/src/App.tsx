import { BrowserRouter as Router, Routes, Route, Link, useNavigate } from 'react-router-dom';
import { GoogleOAuthProvider } from '@react-oauth/google';
import { Toaster } from 'react-hot-toast';
import toast from 'react-hot-toast';
import { Shield, Home, FileText, Activity, GitBranch, Users, Building2, Settings, LogOut, User as UserIcon } from 'lucide-react';
import { useAuthStore } from './store/authStore';
import { logout as apiLogout } from './services/api';
import Dashboard from './components/Dashboard';
import PolicyGenerator from './components/PolicyGenerator';
import AuditView from './components/AuditView';
import AccessGraphView from './components/AccessGraphView';
import IdentityCenterView from './components/IdentityCenterView';
import OrganizationsView from './components/OrganizationsView';
import SettingsView from './components/SettingsView';
import Login from './components/Login';
import ProtectedRoute from './components/ProtectedRoute';

// Get Google Client ID from environment
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

function AppContent() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        />
      </Routes>
    </Router>
  );
}

function MainLayout() {
  const navigate = useNavigate();
  const { user, logout } = useAuthStore();

  const handleLogout = async () => {
    try {
      await apiLogout();
      logout();
      toast.success('Logged out successfully');
      navigate('/login');
    } catch (error) {
      console.error('Logout error:', error);
      toast.error('Failed to logout');
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <Toaster position="top-right" />

      {/* Navigation */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-primary-500" />
              <span className="ml-2 text-xl font-bold">IAM Copilot</span>
            </div>
            <div className="flex items-center space-x-4">
              <NavLink to="/" icon={<Home size={18} />} text="Dashboard" />
              <NavLink to="/generate" icon={<FileText size={18} />} text="Generate Policy" />
              <NavLink to="/audit" icon={<Activity size={18} />} text="Audit" />
              <NavLink to="/graph" icon={<GitBranch size={18} />} text="Access Graph" />
              <NavLink to="/identity-center" icon={<Users size={18} />} text="Identity Center" />
              <NavLink to="/organizations" icon={<Building2 size={18} />} text="Organizations" />
              <NavLink to="/settings" icon={<Settings size={18} />} text="Settings" />

              {/* User Menu */}
              <div className="flex items-center space-x-3 ml-6 pl-6 border-l border-gray-700">
                {user?.avatar_url ? (
                  <img
                    src={user.avatar_url}
                    alt={user.full_name || user.email}
                    className="h-8 w-8 rounded-full"
                  />
                ) : (
                  <div className="h-8 w-8 rounded-full bg-primary-500 flex items-center justify-center">
                    <UserIcon size={18} />
                  </div>
                )}
                <div className="flex flex-col">
                  <span className="text-sm font-medium text-white">
                    {user?.full_name || user?.email}
                  </span>
                  <span className="text-xs text-gray-400">{user?.email}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
                  title="Logout"
                >
                  <LogOut size={18} />
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/generate" element={<PolicyGenerator />} />
          <Route path="/audit" element={<AuditView />} />
          <Route path="/graph" element={<AccessGraphView />} />
          <Route path="/identity-center" element={<IdentityCenterView />} />
          <Route path="/organizations" element={<OrganizationsView />} />
          <Route path="/settings" element={<SettingsView />} />
        </Routes>
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <p className="text-center text-gray-400">
            IAM Copilot v1.0.0 - AI-Powered AWS IAM Management
          </p>
        </div>
      </footer>
    </div>
  );
}

function NavLink({ to, icon, text }: { to: string; icon: React.ReactNode; text: string }) {
  return (
    <Link
      to={to}
      className="flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
    >
      {icon}
      <span>{text}</span>
    </Link>
  );
}

function App() {
  if (!GOOGLE_CLIENT_ID) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center text-white">
          <h1 className="text-2xl font-bold mb-4">Configuration Error</h1>
          <p className="text-gray-400">
            VITE_GOOGLE_CLIENT_ID is not set. Please configure Google OAuth credentials.
          </p>
        </div>
      </div>
    );
  }

  return (
    <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
      <AppContent />
    </GoogleOAuthProvider>
  );
}

export default App;
