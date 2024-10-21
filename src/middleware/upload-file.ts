import multer from "multer";
import multerS3 from "multer-s3"
import s3 from "../core/config/s3";
import { envs } from "../core/config/env";

// Middleware pour multer le telechargement des fichiers sur le bucketS3/Minio
const upload = multer({
    storage: multerS3({
        s3: s3,
        bucket: envs.AWS_BUCKET_NAME,
        acl:  "public-read",
        metadata: (req, file, cb) => {
            cb(null, {fieldName: file.fieldname});
        },
        key(req, file, callback) {
            const uniqueSuffix = `${Date.now()}-${file.originalname}`;
            callback(null,  uniqueSuffix)
        },
    })
});

export default upload;