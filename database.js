const { v4: uuidv4 } = require('uuid');
const { getCachedConfig, getCachedSecrets } = require('@shake-shack/lambda-utils');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const {
    DynamoDBDocumentClient, UpdateCommand, PutCommand, QueryCommand, GetCommand, DeleteCommand,
} = require('@aws-sdk/lib-dynamodb');
const { Pool } = require('pg');

const { CUSTOMER_PROFILE_TABLE_NAME, OKTA_CACHE_ACCESS_TOKEN_TABLE_NAME } = process.env;
const { ALLERGENS_TABLE_NAME } = process.env;

const ddbConfig = {
    marshallOptions: {
        convertEmptyValues: true,
        removeUndefinedValues: true,
    },
};
const { CACHED_SECRETS_FILE_NAME } = process.env;
const ddbClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const documentClient = DynamoDBDocumentClient.from(ddbClient, ddbConfig);
const ssmaSyncAppConfigPath = process.env.SSMA_SYNC_APPCONFIG_FLAG_PATH || '';

/**
 * Queries the ssma_auth_id GSI to look up the customer's profile by their
 * ssma_auth_id. If the profile exists, gets the rest of the profile data.
 * Queries the auth0_id GSI to look up the customer's profile by their
 * auth0_id. If the profile exists, gets the rest of the profile data.
 * @param {object} customerInfo - The ssma_auth_id and auth0_id of this customerInfo.
 * @returns {Promise<object|null>} - The customer's profile if it exists.
 */
let pool;
let cachedSecrets;
async function getPool() {
    if (!pool) {
        if (!cachedSecrets) {
            cachedSecrets = getCachedSecrets(CACHED_SECRETS_FILE_NAME);
        }
        const { CUSTOMERDB_POSTGRESQL_CREDENTIALS } = cachedSecrets;
        const customerCredentials = JSON.parse(CUSTOMERDB_POSTGRESQL_CREDENTIALS);
        pool = new Pool({
            host: customerCredentials.host,
            port: customerCredentials.port,
            user: customerCredentials.username,
            password: customerCredentials.password,
            database: customerCredentials.database,
            ssl: {
                rejectUnauthorized: false,
            },
            max: 10,
            idleTimeoutMillis: 10000,
        });
        console.log('PostgreSQL connection pool created');
    }
    return pool;
}
let UserIdsEnabled = null;
let UserIdsEnabledPromise = null;
async function isUserIdsEnabled() {
    if (UserIdsEnabled !== null) return UserIdsEnabled;
    if (!UserIdsEnabledPromise) {
        UserIdsEnabledPromise = (async () => {
            try {
                const config = await getCachedConfig(ssmaSyncAppConfigPath);
                UserIdsEnabled = config?.enable_postgres_guest_id === true;
                console.log('Loaded flag:', UserIdsEnabled);
            } catch (err) {
                console.error('Error fetching flag:', err);
                UserIdsEnabled = false;
            }
            return UserIdsEnabled;
        })();
    }
    return UserIdsEnabledPromise;
}

exports.getCustomerProfile = async (auth0Id, authId) => {
    let profile = null;
    // eslint-disable-next-line
    const UserIdsEnabled = await isUserIdsEnabled();
    if (UserIdsEnabled) {
        try {
            const dbPools = await getPool();
            const result = await dbPools.query(
                'SELECT * FROM user_account WHERE auth0_id = $1 LIMIT 1',
                [auth0Id],
            );
            // eslint-disable-next-line
            if (result.rows.length > 0) {
                // eslint-disable-next-line
                profile = result.rows[0];
                console.log('PostgreSQL profile found');
            } else {
                console.log('No profile found in PostgreSQL');
            }
        } catch (err) {
            console.error('Postgres query error:', err);
        }
        return profile;
    }
    try {
        const query = buildGetQuery(auth0Id, authId);
        const queryCommand = new QueryCommand(query);
        const queryRes = await documentClient.send(queryCommand);
        if (queryRes.Count) {
            const getCommand = new GetCommand({
                TableName: CUSTOMER_PROFILE_TABLE_NAME,
                Key: { id: queryRes.Items[0].id },
            });
            const getRes = await documentClient.send(getCommand);
            return getRes.Item;
        }

        return null;
    } catch (error) {
        console.error('DynamoDB query error:', error);
    }

    return profile;
};

/**
 * Creates a customer profile for the given customer.
 *
 * @param {object} customerInfo - The customer's info to save.
 * @returns {Promise<object>} - The newly created customer profile.
 */
exports.createCustomerProfile = async (customerInfo) => {
    // eslint-disable-next-line
    const UserIdsEnabled = await isUserIdsEnabled();
    const uuid = uuidv4(); // uuid to insert into postgres or dynamodb
    if (UserIdsEnabled) {
        try {
            const dbPools = await getPool();
            const insertQuery = `
       INSERT INTO user_account (
         first_name,
         last_name,
         email_address,
         email_verification_status,
         phone_number,
         uuid,
         auth0_id,
         created_at,
         user_type
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9
       )
       RETURNING *;
     `;
            console.log('create customerInfo.emailVerificationStatus', customerInfo.emailVerificationStatus);
            const values = [
                customerInfo.firstName ? customerInfo.firstName.toLowerCase() : '.',
                customerInfo.lastName ? customerInfo.lastName.toLowerCase() : '.',
                customerInfo.email?.toLowerCase(),
                customerInfo.emailVerificationStatus || null,
                customerInfo.phoneNumber || null,
                uuid,
                customerInfo.auth0Id || null,
                new Date().toISOString(),
                'g', // default user_type as per schema
            ];
            const result = await dbPools.query(insertQuery, values);
            console.log('Inserted into PostgreSQL');
            return result.rows[0];
        } catch (err) {
            console.error('Postgres insert error:', err);
            throw err;
        }
    }
    const customerItem = {
        id: uuid,
        created_at: new Date().toISOString(),
        email_verification_status: customerInfo?.emailVerificationStatus,
    };

    if (customerInfo.email && typeof customerInfo.email === 'string') {
        customerItem.email_address = customerInfo.email.toLowerCase();
    }

    if (customerInfo.firstName && typeof customerInfo.firstName === 'string') {
        customerItem.first_name = customerInfo.firstName?.toLowerCase();
        customerItem.display_first_name = customerInfo.firstName;
    } else {
        // Add a dot if firstName is not provided
        customerItem.first_name = '.';
        customerItem.display_first_name = '.';
    }

    if (customerInfo.lastName && typeof customerInfo.lastName === 'string') {
        customerItem.last_name = customerInfo.lastName?.toLowerCase();
        customerItem.display_last_name = customerInfo.lastName;
    } else {
        // Add a dot if lastName is not provided
        customerItem.last_name = '.';
        customerItem.display_last_name = '.';
    }

    if (customerInfo.phoneNumber && typeof customerInfo.phoneNumber === 'string') {
        customerItem.phone_number = customerInfo.phoneNumber;
    }

    if (customerInfo.auth0Id) {
        customerItem.auth0_id = customerInfo.auth0Id;
    }

    if (customerInfo.userId) {
        customerItem.ssma_profile_id = customerInfo.userId;
    }

    if (customerInfo.authId) {
        customerItem.ssma_auth_id = customerInfo.authId;
    }

    const putCommand = new PutCommand({
        TableName: CUSTOMER_PROFILE_TABLE_NAME,
        Item: customerItem,
    });
    await documentClient.send(putCommand);

    return customerItem;
};

/**
 * Updates a given customer's profile.
 *
 * @param {string} customerId - The id of the customer's profile.
 * @param {object} updateData - The data to update.
 * @returns {Promise<object>} - The updated customer profile.
 */
exports.updateCustomerProfile = async (customerId, updateData) => {
    // eslint-disable-next-line
    const UserIdsEnabled = await isUserIdsEnabled();
    if (UserIdsEnabled) {
        const dbPools = await getPool();
        const allowedFields = ['first_name', 'last_name', 'phone_number', 'birthday', 'allergens', 'email_verification_status', 'auth0_id'];
        const filteredUpdateData = {};
        // eslint-disable-next-line
        for (const key of allowedFields) {
            if (Object.hasOwn(updateData, key)) {
                const value = updateData[key];
                if (key === 'birthday') {
                    if (value === null) {
                        filteredUpdateData.birthday = null;
                    } else if (typeof value === 'string' && value.includes('-')) {
                        const [month, day] = value.split('-');
                        if (month && day) {
                            filteredUpdateData.birthday = `1904-${month}-${day}`;
                        }
                    }
                } else if (key === 'phone_number') {
                    filteredUpdateData.phone_number = value.startsWith('+1') ? value : `+1${value}`;
                } else if (key === 'allergens' && Array.isArray(value)) {
                    filteredUpdateData.allergens = value.join(',');
                } else if (value != null) {
                    filteredUpdateData[key] = value;
                }
            }
        }
        const updateFields = Object.keys(filteredUpdateData)
            .map((key, index) => `"${key}" = $${index + 2}`)
            .join(', ');
        const values = [customerId, ...Object.values(filteredUpdateData)];
        const updateQuery = `UPDATE user_account SET ${updateFields} WHERE uuid = $1 RETURNING *`;
        const res = await dbPools.query(updateQuery, values);
        if (res.rows.length === 0) {
            throw new Error(`No user found with uuid: ${customerId}`);
        }
        console.log('Returning updated user from PostgreSQL:');
        return res.rows[0];
    }
    const attributes = Object.keys(updateData);

    const updateCommand = new UpdateCommand({
        TableName: CUSTOMER_PROFILE_TABLE_NAME,
        Key: {
            id: customerId,
        },
        UpdateExpression: `SET ${attributes.map((attribute) => `#${attribute}=:${attribute}`).join(',')}`,
        ExpressionAttributeNames: attributes.reduce((accumulator, attribute) => {
            accumulator[`#${attribute}`] = attribute;
            return accumulator;
        }, {}),
        ExpressionAttributeValues: attributes.reduce((accumulator, attribute) => {
            accumulator[`:${attribute}`] = updateData[attribute];
            return accumulator;
        }, {}),
        ReturnValues: 'ALL_NEW',
    });
    const updateRes = await documentClient.send(updateCommand);

    return updateRes.Attributes;
};

exports.getAllergens = async () => {
    const params = {
        TableName: ALLERGENS_TABLE_NAME,
        Key: { allergens_id: 'v2' },
    };
    return documentClient.send(new GetCommand(params));
};

function buildGetQuery(auth0Id, authId) {
    if ((!auth0Id && authId) || (auth0Id && authId)) { // ssma and migrated user
        return {
            TableName: CUSTOMER_PROFILE_TABLE_NAME,
            IndexName: 'ssma_auth_id_gsi',
            KeyConditionExpression: 'ssma_auth_id = :ssma_auth_id',
            ExpressionAttributeValues: { ':ssma_auth_id': authId },
            ProjectionExpression: 'id',
        };
    }
    return {
        TableName: CUSTOMER_PROFILE_TABLE_NAME,
        IndexName: 'auth0_user_id_gsi',
        KeyConditionExpression: 'auth0_id = :auth0_id',
        ExpressionAttributeValues: { ':auth0_id': auth0Id },
        ProjectionExpression: 'id',
    };
}

// Functions get cache okta acccess token upto expiry time
exports.getToken = async () => {
    const parameters = {
        TableName: OKTA_CACHE_ACCESS_TOKEN_TABLE_NAME,
        Key: {
            id: 'auth0_access_token',
        },
    };
    const getResult = await documentClient.send(new GetCommand(parameters));
    return getResult.Item;
};

// Functions to store/cache okta acccess token upto expiry time
exports.cacheToken = async (token) => {
    const currTimestamp = Date.now();
    const expTimestamp = currTimestamp + ((token.expires_in - 60) * 1000);
    const parameters = {
        TableName: OKTA_CACHE_ACCESS_TOKEN_TABLE_NAME,
        Key: {
            id: 'auth0_access_token',
        },
        UpdateExpression: 'SET access_token = :access_token, expiry_timestamp = :currentTimeStamp',
        ConditionExpression: 'attribute_not_exists(access_token) OR (attribute_exists(access_token) AND expiry_timestamp < :currentTimeStamp)',
        ExpressionAttributeValues: {
            ':access_token': token.access_token,
            ':currentTimeStamp': expTimestamp,
        },
        ReturnValues: 'ALL_NEW',
    };
    const updateCommands = new UpdateCommand(parameters);
    const updateResult = await documentClient.send(updateCommands);
    return updateResult.Attributes;
};

/*
* Queries the email_address_gsi GSI to look up the customer's profile by their
* email. If the profile exists, gets the rest of the profile data.
* @param {object} customerInfo - The email of this customerInfo.
* @returns {Promise<object|null>} - The customer's profile if it exists.
*/

exports.getCustomerProfileByEmail = async (email) => {

    const UserIdsEnabled = await isUserIdsEnabled();
    console.log('is guestidd flag enabled:', UserIdsEnabled);
    if (UserIdsEnabled) {
        const dbPools = await getPool();
        const normalizedEmail = email.trim().toLowerCase();
        const res = await dbPools.query('SELECT * FROM user_account WHERE (email_address) = $1', [normalizedEmail]);
        return res.rows.length ? res.rows[0] : null;
    }
    const queryCommand = new QueryCommand({
        TableName: CUSTOMER_PROFILE_TABLE_NAME,
        IndexName: 'email_address_gsi',
        KeyConditionExpression: 'email_address = :email',
        ExpressionAttributeValues: { ':email': email },
        ProjectionExpression: 'id',
    });
    const queryRes = await documentClient.send(queryCommand);
    if (queryRes.Count) {
        const getCommand = new GetCommand({
            TableName: CUSTOMER_PROFILE_TABLE_NAME,
            Key: { id: queryRes.Items[0].id },
        });
        const getRes = await documentClient.send(getCommand);
        return getRes.Item;
    }

    return null;
};

exports.deleteItemById = async (id) => {
    const query = new DeleteCommand({
        TableName: process.env.KOUNT_TABLE_NAME,
        Key: { session_id: id },
    });
    return await documentClient.send(query);
};
exports.isUserIdsEnabled = isUserIdsEnabled;
exports.getPool = getPool;