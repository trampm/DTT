import React, { useState, useEffect } from 'react';
import adminService from '../../services/adminService';
import { useNavigate } from 'react-router-dom';
import { TextField, Button, Container, Typography, Alert, FormControl, InputLabel, Select, MenuItem } from '@mui/material';

const AssignPermission = () => {
  const [roleId, setRoleId] = useState('');
  const [permissionId, setPermissionId] = useState('');
  const [roles, setRoles] = useState([]);
  const [permissions, setPermissions] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const rolesData = await adminService.getRoles(); // Assuming getRoles returns a list of roles
        setRoles(rolesData);

        const permissionsData = await adminService.getPermissions(); // Assuming getPermissions returns a list of permissions
        setPermissions(permissionsData);
      } catch (err) {
        setError(err.response?.data?.message || 'Не удалось загрузить роли или права.');
      }
    };

    fetchData();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    try {
      await adminService.assignPermissionToRole({ roleId: parseInt(roleId, 10), permissionId: parseInt(permissionId, 10) });
      setMessage('Право успешно назначено роли!');
      setRoleId(''); // Очищаем поля формы
      setPermissionId('');
      navigate('/admin/roles'); // Redirect to roles list (or wherever appropriate)
    } catch (err) {
      setError(err.response?.data?.message || 'Не удалось назначить право роли.');
    }
  };

  return (
    <Container maxWidth="sm">
      <Typography variant="h4" align="center" gutterBottom>
        Назначить право роли
      </Typography>
      {message && <Alert severity="success">{message}</Alert>}
      {error && <Alert severity="error">{error}</Alert>}
      <form onSubmit={handleSubmit}>
        <FormControl fullWidth margin="normal">
          <InputLabel id="role-label">Роль</InputLabel>
          <Select
            labelId="role-label"
            value={roleId}
            onChange={(e) => setRoleId(e.target.value)}
            required
          >
            {roles.map((role) => (
              <MenuItem key={role.id} value={role.id}>
                {role.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl fullWidth margin="normal">
          <InputLabel id="permission-label">Право</InputLabel>
          <Select
            labelId="permission-label"
            value={permissionId}
            onChange={(e) => setPermissionId(e.target.value)}
            required
          >
            {permissions.map((permission) => (
              <MenuItem key={permission.id} value={permission.id}>
                {permission.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button type="submit" variant="contained" color="primary" fullWidth>
          Назначить право
        </Button>
      </form>
    </Container>
  );
};

export default AssignPermission;