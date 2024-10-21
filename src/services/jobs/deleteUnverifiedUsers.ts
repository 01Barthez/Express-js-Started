import usersControllers from '@src/controllers/users-controllers';
import {CronJob} from 'cron';

const deleteInvalidUser = new CronJob (
    '0 0 0 * * *', // cronTime
	async() => {
		await usersControllers.DeleteUNVERIFIED();
        console.log('Not verified user ddeleted !');
	},
	null, // onComplete
	true, // start
);

export default deleteInvalidUser