import { Resend } from 'resend';
import dotenv from 'dotenv';
dotenv.config();

if(process.env.RESEND_API) {
    console.log("ESTA CHAVE DO RESEND NAO ESTA NO ARQUIVO .ENV");
}

const resend = new Resend(process.env.RESEND_API);

const sendEmail = async ({sendTo, subject, html}) => {
    try {
        const { data, error } = await resend.emails.send({
            from: 'eCommerceProject <onboarding@resend.dev>',
            to: sendTo,
            subject: subject,
            html: html,
        });

        if(error) {
            return console.error({error});
        }

        return data
    } catch (error) {
        console.log('ERRO AO ENVIAR EMAIL', error);
    }
}

export default sendEmail;