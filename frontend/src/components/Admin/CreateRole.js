import React, { useState } from 'react';
import adminService from '../../services/adminService';
import { useNavigate } from 'react-router-dom';
import { TextField, Button, Container, Typography, Alert } from '@mui/material';

const CreateRole = () => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    try {
      await adminService.createRole({ name, description });
      setMessage('Роль успешно создана!');
      setName(''); // Очищаем поля формы
      setDescription('');
      navigate('/admin/roles'); // Redirect to roles list
    } catch (err) {
      setError(err.response?.data?.message || 'Не удалось создать роль.');
    }
  };

  return (
    <Container maxWidth="sm">
      <Typography variant="h4" align="center" gutterBottom>
        Создать роль
      </Typography>
      {message && <Alert severity="success">{message}</Alert>}
      {error && <Alert severity="error">{error}</Alert>}
      <form onSubmit={handleSubmit}>
        <TextField
          fullWidth
          margin="normal"
          label="Название роли"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <TextField
          fullWidth
          margin="normal"
          label="Описание роли"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <Button type="submit" variant="contained" color="primary" fullWidth>
          Создать роль
        </Button>
      </form>
    </Container>
  );
};

export default CreateRole;