import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Login from './components/Auth/Login';
import Register from './components/Auth/Register';
import Profile from './components/Profile/Profile';
import UpdateProfile from './components/Profile/UpdateProfile';
import Navigation from './components/Navigation';
import PrivateRoute from './components/PrivateRoute';
import Logout from './components/Auth/Logout';
import PasswordReset from './components/Auth/PasswordReset';
import PasswordResetConfirm from './components/Auth/PasswordResetConfirm';
import CreateRole from './components/Admin/CreateRole';
import CreatePermission from './components/Admin/CreatePermission';
import AssignRole from './components/Admin/AssignRole';
import AssignPermission from './components/Admin/AssignPermission';
import { Container } from '@mui/material';
import './App.css';

function App() {
  return (
    <Router>
      <Navigation />  {/* Add the navigation component */}
      <Container>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/logout" element={<Logout />} />
          <Route path="/password-reset" element={<PasswordReset />} />
           <Route path="/password-reset/confirm" element={<PasswordResetConfirm />} />

          <Route
            path="/profile"
            element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            }
          />
          <Route
            path="/update-profile"
            element={
              <PrivateRoute>
                <UpdateProfile />
              </PrivateRoute>
            }
          />

          {/* Admin Routes (Example) */}
          <Route
            path="/admin/create-role"
            element={
              <PrivateRoute>
                <CreateRole />
              </PrivateRoute>
            }
          />
          <Route
            path="/admin/create-permission"
            element={
              <PrivateRoute>
                <CreatePermission />
              </PrivateRoute>
            }
          />
          <Route
            path="/admin/assign-role"
            element={
              <PrivateRoute>
                <AssignRole />
              </PrivateRoute>
            }
          />
          <Route
            path="/admin/assign-permission"
            element={
              <PrivateRoute>
                <AssignPermission />
              </PrivateRoute>
            }
          />
        </Routes>
      </Container>
    </Router>
  );
}

export default App;