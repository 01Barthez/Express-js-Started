import bcrypt from 'bcrypt'

const hashText = async (plainText: string) => {
    const getRounds = 10;
    const salt = await bcrypt.genSalt(getRounds);
    const hashPassword = await bcrypt.hash(plainText, salt);
    
    return hashPassword; 
}

const comparePassword = async (comparePlainText: string, compareHashPassword: string) => {
    const resultat = await bcrypt.compare(comparePlainText, compareHashPassword);
    return resultat;
}

export {hashText, comparePassword};