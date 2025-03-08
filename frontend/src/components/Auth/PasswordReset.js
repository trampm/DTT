import React, { useState } from 'react';
import authService from '../../services/authService';
import { TextField, Button, Container, Typography, Alert } from '@mui/material';

const PasswordReset = () => {
    const [email, setEmail] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setMessage('');
        try {
            await authService.initiatePasswordReset(email); // Assume this function exists in authService
            setMessage('Инструкции по сбросу пароля отправлены на вашу электронную почту.');
        } catch (err) {
            setError(err.response?.data?.message || 'Произошла ошибка при отправке запроса на сброс пароля.');
        }
    };

    return (
        <Container maxWidth="sm">
            <Typography variant="h4" align="center" gutterBottom>
                Сброс пароля
            </Typography>
            {message && <Alert severity="success">{message}</Alert>}
            {error && <Alert severity="error">{error}</Alert>}
            <form onSubmit={handleSubmit}>
                <TextField
                    fullWidth
                    margin="normal"
                    label="Email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                />
                <Button type="submit" variant="contained" color="primary" fullWidth>
                    Отправить запрос на сброс пароля
                </Button>
            </form>
        </Container>
    );
};

export default PasswordReset;