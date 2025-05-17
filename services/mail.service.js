const nodemailer = require("nodemailer");
const config = require("config");

class MailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: "gmail",
      host: config.get("smtp_host"),
      port: config.get("smtp_port"),
      secure: false,
      auth: {
        user: config.get("smtp_user"),
        pass: config.get("smtp_password"),
      },
    });
  }

  async sendMail(toEmail, link) {
    await this.transporter.sendMail({
      from: config.get("smtp_user"),
      to: toEmail,
      subject: "ITTERM akkountini faollashtirish",
      text: "",
      html: `
<!DOCTYPE html>
<html lang="uz">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Akkountni faollashtirish</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); text-align: center;">
    <h2 style="color: #333;">Akkountni faollashtirish</h2>
    <p style="font-size: 16px; color: #555;">Hurmatli foydalanuvchi, iltimos, akkountingizni faollashtirish uchun quyidagi tugmani bosing:</p>
    <a href="${link}" style="display: inline-block; margin-top: 20px; background-color: #4CAF50; color: white; text-decoration: none; padding: 12px 25px; border-radius: 5px; font-size: 16px;">
      Akkountni faollashtirish
    </a>
    <p style="margin-top: 30px; font-size: 12px; color: #999;">Agar bu siz emas bo‘lsangiz, bu xatni e'tiborsiz qoldiring.</p>
  </div>
</body>
</html>
`,
    });
  }
}

module.exports = new MailService();
