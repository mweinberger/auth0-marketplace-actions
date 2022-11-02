exports.onExecutePreUserRegistration = async(event, api) => {
	const Pangea = require('node-pangea');
	const domain = "aws.us.pangea.cloud";
	const token = event.secrets.TOKEN;
	const configId = event.configuration.CONFIGID;
	const config = new Pangea.PangeaConfig({
			domain: domain,
			configId: configId
	});
	const audit = new Pangea.AuditService(token, config);
	const embargo = new Pangea.EmbargoService(token, config);
	const domainIntel = new Pangea.DomainIntelService(token, config);

	const data = {
			actor: event.user.email,
			action: "Registration",
			status: "success",
			message: "",
	};
	const ip = event.request.ip;
	console.log("Checking Embargo IP : '%s'", ip);
	const ebmargo_response = await embargo.ipCheck(ip);
	console.log("Response: ", ebmargo_response.result);
	console.log("Checking Domain : '%s'", domain);
	const options = {
			provider: "domaintools",
			verbose: true,
			raw: true
	};
	const domain_response = await domainIntel.lookup(event.user.email.split("@")[1], options);
	console.log(domain_response.result);

	if (ebmargo_response.result.count > 0) {

			const LOCALIZED_MESSAGES = {
						en: 'You are not allowed to register from an embargoed country.',
						es: 'No tienes permitido registrarte.'
					};

			const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
			api.access.deny('no_signups_from_embargo', userMessage);

			data.status = "failed"
				data.message = ebmargo_response.result
				const logResponse = await audit.log(data);
	} else if (domain_response.result.raw_data.response.risk_score > 70) {

			const LOCALIZED_MESSAGES = {
						en: 'You are not allowed to register with a suspicious email domain.',
						es: 'No tienes permitido registrarte.'
					};

			const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
			api.access.deny('no_signups_from_sus_domain', userMessage);

			data.status = "failed"
				data.message = domain_response.result
				const logResponse = await audit.log(data);
	} else {

			data.message = "User successfully registered"
				const logResponse = await audit.log(data);
	};
};
