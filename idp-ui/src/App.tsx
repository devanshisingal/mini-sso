import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { MfaEnroll } from './pages/MfaEnroll';
import { MfaVerify } from './pages/MfaVerify';
import { Account } from './pages/Account';
import { AdminDashboard } from './pages/AdminDashboard';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/mfa-enroll" element={<MfaEnroll />} />
        <Route path="/mfa-verify" element={<MfaVerify />} />
        <Route path="/account" element={<Account />} />
        <Route path="/admin" element={<AdminDashboard />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
