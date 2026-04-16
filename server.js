require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Resend } = require('resend');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');

const app = express();

// ВАЖНО для Render: чтобы rate-limiter видел реальные IP пользователей, а не IP балансировщика
app.set('trust proxy', 1);

app.use(express.json());
// Разрешаем запросы с любого сайта. Когда выложишь сайт на домен, замени '*' на 'https://твой-сайт.ru'
app.use(cors({ origin: '*' }));

// --- НАСТРОЙКА ЗАЩИТЫ ОТ СПАМА (Rate Limiting) ---
// Ограничение: максимум 5 запросов кода с одного IP в течение 15 минут
const requestCodeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { error: 'Слишком много запросов. Попробуйте позже.' }
});

// Ограничение: максимум 10 попыток проверки кода с одного IP в течение 10 минут
const verifyCodeLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    message: { valid: false, message: 'Слишком много попыток. Попробуйте позже.' }
});

// --- ИНИЦИАЛИЗАЦИЯ ---
const resend = new Resend(process.env.RESEND_API_KEY);

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

// ---------------------------------------------------------
// 1. ЗАПРОС КОДА (Генерация и отправка письма)
// ---------------------------------------------------------
app.post('/api/verification/request', requestCodeLimiter, async (req, res) => {
    try {
        const { email, purpose } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email обязателен' });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const challengeId = crypto.randomUUID();

        // Сохраняем в БД: код, время жизни (5 мин) и счетчик попыток (0)
        await db.collection('verification_codes').doc(challengeId).set({
            email: email,
            code: code,
            purpose: purpose || 'login',
            attempts: 0, // ТЕ САМЫЕ 3 ПОПЫТКИ
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: Date.now() + 5 * 60 * 1000 
        });

        const title = purpose === 'registration' ? 'Подтверждение регистрации' : 'Вход в аккаунт';

        // ТВОЙ ШАБЛОН ПИСЬМА
        const htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
              <div style="background: white; border-radius: 10px; padding: 30px; text-align: center;">
                <h1 style="color: #7C3AED; margin-bottom: 20px;">Spark</h1>
                <h2 style="color: #333;">${title}</h2>
                <p style="color: #666; margin-bottom: 30px;">Используйте этот код для продолжения</p>
                
                <div style="background: linear-gradient(135deg, #7C3AED 0%, #A78BFA 100%); border-radius: 10px; padding: 20px; margin: 20px 0;">
                  <div style="font-size: 36px; font-weight: bold; color: white; letter-spacing: 5px;">${code}</div>
                </div>
                
                <p style="color: #999; font-size: 14px; margin-top: 20px;">
                  Код действителен в течение <strong>5 минут</strong>.<br>
                  У вас есть <strong>3 попытки</strong> для ввода кода.
                </p>
                
                <div style="background: #FEF3C7; border-left: 4px solid #F59E0B; padding: 15px; margin-top: 20px; text-align: left;">
                  <p style="color: #92400E; margin: 0; font-size: 14px;">
                    ⚠️ Если вы не запрашивали этот код, просто проигнорируйте это письмо.
                  </p>
                </div>
              </div>
            </div>
        `;

        const { data, error } = await resend.emails.send({
            from: 'Spark App noreply@spark-messenger.ru',
            to: [email],
            subject: `${code} — Код подтверждения Spark`,
            html: htmlContent,
        });

        if (error) {
            console.error('Ошибка Resend:', error);
            return res.status(500).json({ error: 'Не удалось отправить письмо' });
        }

        res.status(200).json({ challengeId: challengeId });

    } catch (error) {
        console.error('Ошибка сервера:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ---------------------------------------------------------
// 2. ПРОВЕРКА КОДА (При вводе юзером)
// ---------------------------------------------------------
app.post('/api/verification/verify', verifyCodeLimiter, async (req, res) => {
    try {
        const { challengeId, code, purpose } = req.body;

        if (!challengeId || !code) {
            return res.status(400).json({ valid: false, message: 'Отсутствуют данные' });
        }

        const docRef = db.collection('verification_codes').doc(challengeId);
        const doc = await docRef.get();

        if (!doc.exists) {
            return res.status(400).json({ valid: false, message: 'Код не найден или истек' });
        }

        const data = doc.data();

        // 1. Проверка времени (5 минут)
        if (Date.now() > data.expiresAt) {
            await docRef.delete();
            return res.status(400).json({ valid: false, message: 'Время действия кода истекло' });
        }

        // 2. Проверка назначения
        if (data.purpose !== purpose) {
            return res.status(400).json({ valid: false, message: 'Системная ошибка. Запросите код заново' });
        }

        // 3. Проверка лимита попыток (максимум 3)
        if (data.attempts >= 3) {
            await docRef.delete();
            return res.status(400).json({ valid: false, message: 'Превышено количество попыток. Запросите новый код.' });
        }

        // 4. Проверка правильности кода
        if (data.code !== code) {
            const newAttempts = (data.attempts || 0) + 1;
            await docRef.update({ attempts: newAttempts }); // Увеличиваем счетчик ошибок
            
            const attemptsLeft = 3 - newAttempts;
            if (attemptsLeft === 0) {
                await docRef.delete();
                return res.status(400).json({ valid: false, message: 'Попытки исчерпаны. Запросите новый код.' });
            }
            
            return res.status(400).json({ valid: false, message: `Неверный код. Осталось попыток: ${attemptsLeft}` });
        }

        // Если всё верно — удаляем код из базы
        await docRef.delete();
        res.status(200).json({ valid: true });

    } catch (error) {
        console.error('Ошибка проверки:', error);
        res.status(500).json({ valid: false, message: 'Внутренняя ошибка сервера' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Verification Server запущен на порту ${PORT}`);
});
