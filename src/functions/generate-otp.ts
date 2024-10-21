import otpGenerator from 'otp-generator';

function generateSimpleOTP(): string {
    const otpGenerate = otpGenerator.generate(
        6, // Number of Caracters
        { 
            digits: true, 
            lowerCaseAlphabets: false, 
            upperCaseAlphabets: false, 
            specialChars: false 
        }
    );

    // Return a string of number who will be our otp Number
    return otpGenerate; 
}

export default generateSimpleOTP;