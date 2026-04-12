import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({ origin: true })); // Разрешает все источники

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const challenges = new Map();

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateChallengeId() {
  return crypto.randomBytes(16).toString('hex');
}

function sendCodeEmail(email, code, purpose) {
  const subject = purpose === 'registration'
    ? 'Подтверждение регистрации в Spark'
    : 'Код подтверждения входа в Spark';
  
  const title = purpose === 'registration'
    ? 'Подтверждение регистрации'
    : 'Код подтверждения';

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
      <div style="background: white; border-radius: 10px; padding: 30px; text-align: center;">
        <h1 style="color: #7C3AED; margin-bottom: 20px;">Spark</h1>
        <h2 style="color: #333;">${title}</h2>
        <p style="color: #666; margin-bottom: 30px;">Используйте этот код для входа в ваш аккаунт</p>
        
        <div style="background: linear-gradient(135deg, #7C3AED 0%, #A78BFA 100%); border-radius: 10px; padding: 20px; margin: 20px 0;">
          <div style="font-size: 36px; font-weight: bold; color: white; letter-spacing: 5px;">${code}</div>
        </div>
        
        <p style="color: #999; font-size: 14px; margin-top: 20px;">
          Код действителен в течение <strong>5 минут</strong>.<br>
          У вас есть <strong>3 попытки</strong> для ввода кода.
        </p>
        
        <div style="background: #FEF3C7; border-left: 4px solid #F59E0B; padding: 15px; margin-top: 20px; text-align: left;">
          <p style="color: #92400E; margin: 0; font-size: 14px;">
            ⚠️ Если вы не запрашивали этот код, проигнорируйте это письмо.
          </p>
        </div>
      </div>
    </div>
  `;

  return transporter.sendMail({
    from: `"${process.env.FROM_NAME || 'Spark'}" <${process.env.SMTP_USER}>`,
    to: email,
    subject,
    html
  });
}

app.post('/api/verification/request', async (req, res) => {
  try {
    const { email, purpose } = req.body || {};

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ message: 'Email обязателен' });
    }

    const normalizedPurpose = purpose === 'registration' ? 'registration' : 'login';
    const code = generateCode();
    const challengeId = generateChallengeId();
    const expiresAt = Date.now() + 5 * 60 * 1000;

    challenges.set(challengeId, {
      email: email.toLowerCase(),
      code,
      purpose: normalizedPurpose,
      attempts: 0,
      expiresAt
    });

    await sendCodeEmail(email, code, normalizedPurpose);

    res.json({ success: true, challengeId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Не удалось отправить код' });
  }
});

app.post('/api/verification/verify', (req, res) => {
  try {
    const { challengeId, code, purpose } = req.body || {};
    const challenge = challenges.get(challengeId);

    if (!challenge) {
      return res.status(400).json({ valid: false, message: 'Код не найден. Запросите новый код' });
    }

    if (challenge.purpose !== (purpose === 'registration' ? 'registration' : 'login')) {
      return res.status(400).json({ valid: false, message: 'Некорректный тип кода' });
    }

    if (Date.now() > challenge.expiresAt) {
      challenges.delete(challengeId);
      return res.status(400).json({ valid: false, message: 'Код истёк. Запросите новый код' });
    }

    if (challenge.attempts >= 3) {
      challenges.delete(challengeId);
      return res.status(400).json({ valid: false, message: 'Превышено количество попыток. Запросите новый код' });
    }

    if (String(code) === challenge.code) {
      challenges.delete(challengeId);
      return res.json({ valid: true, message: 'Код подтверждён' });
    }

    challenge.attempts += 1;
    return res.status(400).json({
      valid: false,
      message: `Неверный код. Осталось попыток: ${3 - challenge.attempts}`
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ valid: false, message: 'Ошибка проверки кода' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/', (_req, res) => {
  res.json({
    status: 'Server is running',
    endpoints: {
      health: 'GET /health',
      requestVerification: 'POST /api/verification/request',
      verifyCode: 'POST /api/verification/verify'
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Verification server started on port ${PORT}`);
  console.log(`🎨 Email design: Spark theme with gradient`);
});