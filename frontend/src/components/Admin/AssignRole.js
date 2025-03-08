import React, { useState, useEffect } from 'react';
import adminService from '../../services/adminService';
import { useNavigate } from 'react-router-dom';
import { TextField, Button, Container, Typography, Alert, FormControl, InputLabel, Select, MenuItem } from '@mui/material';

const AssignRole = () => {
  const [userId, setUserId] = useState('');
  const [roleId, setRoleId] = useState('');
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const usersData = await adminService.getUsers(); // Assuming getUsers returns a list of users
        setUsers(usersData);

        const rolesData = await adminService.getRoles(); // Assuming getRoles returns a list of roles
        setRoles(rolesData);
      } catch (err) {
        setError(err.response?.data?.message || 'Не удалось загрузить пользователей или роли.');
      }
    };

    fetchData();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    try {
      await adminService.assignRoleToUser({ userId: parseInt(userId, 10), roleId: parseInt(roleId, 10) });
      setMessage('Роль успешно назначена пользователю!');
      setUserId(''); // Очищаем поля формы
      setRoleId('');
      navigate('/admin/users'); // Redirect to users list
    } catch (err) {
      setError(err.response?.data?.message || 'Не удалось назначить роль пользователю.');
    }
  };

  return (
    <Container maxWidth="sm">
      <Typography variant="h4" align="center" gutterBottom>
        Назначить роль пользователю
      </Typography>
      {message && <Alert severity="success">{message}</Alert>}
      {error && <Alert severity="error">{error}</Alert>}
      <form onSubmit={handleSubmit}>
        <FormControl fullWidth margin="normal">
          <InputLabel id="user-label">Пользователь</InputLabel>
          <Select
            labelId="user-label"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            required
          >
            {users.map((user) => (
              <MenuItem key={user.id} value={user.id}>
                {user.name} ({user.email})
              </MenuItem>
            ))}
          </Select>
        </FormControl>
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
        <Button type="submit" variant="contained" color="primary" fullWidth>
          Назначить роль
        </Button>
      </form>
    </Container>
  );
};

export default AssignRole;