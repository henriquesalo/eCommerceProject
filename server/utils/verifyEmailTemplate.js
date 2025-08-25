const verifyEmailTemplate = ({ name, url }) => {
    return `
        <p>Prezado ${name}</p>
        <p>Obrigado por se Cadastrar no nosso eCommerce</p>
        <a href=${url} style="color:black; background:orange; margin-top:10px, padding:20px,display:block">
            Verifique seu Email    
        </a>
    `;
};

export default verifyEmailTemplate;