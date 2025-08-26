const forgotPasswordTemplate = ({ name, otp }) => {
    return `
        <h1>Olá ${name},</h1>
        <p>Recebemos um pedido para redefinir sua senha. Use o código OTP abaixo para continuar:</p>
        <p>Seu código de verificação é: <strong>${otp}</strong></p>
        <p>Este código é válido por 1 hora. Insira este código no eCommerceProject para prosseguir com a redefinição da sua senha.</p>
        <br/>
        <p>Obrigado</p>
        <p>Equipe eCommerceProject</p>
        <br/>
        <p>Se você não solicitou isso, ignore este e-mail.</p>
    `;
}

export default forgotPasswordTemplate;