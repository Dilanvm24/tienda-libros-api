import jwt from 'jsonwebtoken';
import { User } from '../models/user.model.js';
import bcrypt from 'bcrypt';

export const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // 1. Buscar al usuario
    const user = await User.findOne({ username });

    //  CAMBIO AQUÍ: Usamos bcrypt.compare
    const esValida = user ? await bcrypt.compare(password, user.password) : false;

    // 2. Validar (Muy básico por ahora, luego pondremos encriptación)
    if(!user || !esValida){
      const error = new Error("Credenciales invalidas");
      error.statusCode = 401;
      throw error;
    }

    // 3. Generar el Token (El pase VIP)
    const token = jwt.sign(
      { id: user._id, role: user.role },  // Lo que guardamos dentro del token (Payload)
      process.env.JWT_SECRET,  // La firma secreta
      { expiresIn: '1h'}  // El token caduca en 1 hora
    );

    res.json({ mensaje: 'Login exitoso', token })
  } catch (error) {
    next(error);
  }
}

