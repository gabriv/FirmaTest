var origenCertificados = 'NAVEGADOR';

function Crypt(entidades,nif, esDNIe) {	
	// CAPICOM constantes 
	
	//var CAPICOM_CURRENT_USER_STORE = 2;
	//var CAPICOM_SMART_CARD_USER_STORE = 4;
	
	var CAPICOM_MEMORY_STORE = 0
	var CAPICOM_LOCAL_MACHINE_STORE = 1 
	var CAPICOM_CURRENT_USER_STORE = 2
	var CAPICOM_ACTIVE_DIRECTORY_USER_STORE = 3
	var CAPICOM_SMART_CARD_USER_STORE = 4
	var filtroDNIe = (undefined == esDNIe) ? false : esDNIe;
	
	var CAPICOM_STORE_OPEN_READ_ONLY = 0;
	
	var CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
	var CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY = 6;
	var CAPICOM_CERTIFICATE_FIND_TIME_VALID = 9;
	var CAPICOM_CERTIFICATE_FIND_KEY_USAGE = 12;
	var CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE = 0x00000080;
	var CAPICOM_NON_REPUDIATION_KEY_USAGE = 0x00000040;
	var CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
	var CAPICOM_INFO_SUBJECT_SIMPLE_NAME = 0;
	var CAPICOM_ENCODE_BASE64 = 0;
	var CAPICOM_E_CANCELLED = -2138568446;
	var CERT_KEY_SPEC_PROP_ID = 6;
	
	var CAPICOM_VERIFY_SIGNATURE_ONLY = 0;
	var CAPICOM_VERIFY_SIGNATURE_AND_CERTIFICATE = 1;
	var CAPICOM_CERTIFICATE_FIND_ISSUER_NAME = 2;
	var CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;
	
	
	
	var  CAPICOM_CHECK_ONLINE_ALL = 0x000001EF;
	var  CAPICOM_CHECK_OFFLINE_ALL = 0x000001F7;
	var  CAPICOM_CHECK_NONE = 0x00000000;
	entidadesCA = entidades;
	this.firmar = signedData;
	this.verificar = verifySignature;
	this.obtenerCertificado = getCertificateBase64;
	this.selectCertificado = selectCertificate;
	var autoSelected = false; // indica si el certificado ha sido seleccionado autom�ticamente
	/* CONSTRUCTOR */    
	// permite seleccionar el certificado por el que se va a firmar.    
	var FilteredCertificates = getCertificates(nif);    
	
	var SelectedCertificate;
	var Certificate;

	if(!FilteredCertificates){
		return;
	}
	
	if (FilteredCertificates.Count!=1){
		
		SelectedCertificate = FilteredCertificates.Select();
		Certificate = SelectedCertificate.Item(1);
	}
	else{
		autoSelected = true;
		Certificate = FilteredCertificates.Item(1);
		
	}
		
	var value = "" ,hash = ""; 
	var status = Certificate.IsValid();
	
	status.CheckFlag =  CAPICOM_CHECK_NONE;
	
		
	if (status.Result) {
		//value = SelectedCertificate.Item(1).GetInfo(CAPICOM_INFO_SUBJECT_SIMPLE_NAME);
		//hash  = SelectedCertificate.Item(1).Thumbprint;
		value = Certificate.GetInfo(CAPICOM_INFO_SUBJECT_SIMPLE_NAME);
		hash  = Certificate.Thumbprint;
	} else {
		var Chain = new ActiveXObject("CAPICOM.Chain");
		Chain.Build(Certificate);
			var mensaje = "";
		if (Chain.Status(0) == 64) mensaje = "CAPICOM_TRUST_REVOCATION_STATUS_UNKNOWN";
		else mensaje  = Chain.Status(0);
		alert("Error:  " + mensaje + " -> " + Chain.ExtendedErrorInfo(1));
	}
	
	/**
	* forzar la seleccion del certificado
	*/
	function selectCertificate() {
		if (!autoSelected) return;
		var FilteredCertificates = getCertificates();
		
		var SelectedCertificate = FilteredCertificates.Select();
		var Certificate = SelectedCertificate.Item(1);
		status.CheckFlag =  CAPICOM_CHECK_NONE;
		if (status.Result) {
			//value = SelectedCertificate.Item(1).GetInfo(CAPICOM_INFO_SUBJECT_SIMPLE_NAME);
			//hash  = SelectedCertificate.Item(1).Thumbprint;
			value = Certificate.GetInfo(CAPICOM_INFO_SUBJECT_SIMPLE_NAME);
			hash  = Certificate.Thumbprint;
		} else {
			var Chain = new ActiveXObject("CAPICOM.Chain");
			Chain.Build(Certificate);
				var mensaje = "";
			if (Chain.Status(0) == 64) mensaje = "CAPICOM_TRUST_REVOCATION_STATUS_UNKNOWN";
			else mensaje  = Chain.Status(0);
			alert("Error:  " + mensaje + " -> " + Chain.ExtendedErrorInfo(1));
		}
	}
	
	
	/*
	* obtener los certificados del My
	*/
	function getCertificates(nif){		
		// instantiar los objetos CAPICOM
		var MyStore = new ActiveXObject("CAPICOM.Store");
		var FilteredCertificates = new ActiveXObject("CAPICOM.Certificates");
		// abrir el almacen de certificados del usuario actual 
		try {
			//alert('accediendo a certificado');
		
			MyStore.Open(CAPICOM_CURRENT_USER_STORE, "my", CAPICOM_STORE_OPEN_READ_ONLY);
		
		
			//MyStore.Open(CAPICOM_LOCAL_MACHINE_STORE , "my", 1);
			//alert('certificado seleccionado');
		
		} catch (e) {
			alert("Error: " + e.message);
			return false;
		// if (e.number != CAPICOM_E_CANCELLED) return false;
		}

		// find all of the certificates that:
		//   * Are good for signing data
		//	* Have PrivateKeys associated with then - Note how this is being done :)
		//   * Are they time valid
		//var FilteredCertificates = MyStore.Certificates.Find(CAPICOM_CERTIFICATE_FIND_KEY_USAGE,CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE).Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID).Find(CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY,CERT_KEY_SPEC_PROP_ID);
		var ent = entidadesCA.split(',');
		var certs = new ActiveXObject("CAPICOM.Certificates");	   
		if(ent[0]!=""){
			for(j=0;j<ent.length;j++){
				var FilteredCertificates;			   
				if (nif != null && nif != "") {
					if(filtroDNIe) {
						FilteredCertificates = MyStore.Certificates.Find(CAPICOM_CERTIFICATE_FIND_ISSUER_NAME,ent[j]).Find(CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME,nif).Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID).Find(CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY,CERT_KEY_SPEC_PROP_ID).Find(CAPICOM_CERTIFICATE_FIND_KEY_USAGE,CAPICOM_NON_REPUDIATION_KEY_USAGE);
					} else {		   		
						FilteredCertificates = MyStore.Certificates.Find(CAPICOM_CERTIFICATE_FIND_ISSUER_NAME,ent[j]).Find(CAPICOM_CERTIFICATE_FIND_KEY_USAGE,CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE).Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID).Find(CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY,CERT_KEY_SPEC_PROP_ID).Find(CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME,nif);
					}
				}else {
					if (filtroDNIe) {
						if (ent[j].indexOf("DNIE") != -1){
							FilteredCertificates = MyStore.Certificates.Find(CAPICOM_CERTIFICATE_FIND_ISSUER_NAME,ent[j]).Find(CAPICOM_CERTIFICATE_FIND_KEY_USAGE,CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE).Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID).Find(CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY,CERT_KEY_SPEC_PROP_ID);
						}
					} else {
						FilteredCertificates = MyStore.Certificates.Find(CAPICOM_CERTIFICATE_FIND_ISSUER_NAME,ent[j]).Find(CAPICOM_CERTIFICATE_FIND_KEY_USAGE,CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE).Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID).Find(CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY,CERT_KEY_SPEC_PROP_ID);
					}
				}
				for(i=1;i<=FilteredCertificates.count;i++){			   		
					var cert = FilteredCertificates.Item(i);
					if(origenCertificados == 'TARJETA'){				   		
						if (cert.PrivateKey.IsHardwareDevice()) {				   				
							certs.add(cert);
				}
					}else {				   			   		
						certs.add(cert);
			}
		}
			}
		}
		
		// Clean Up
		MyStore = null;
		
		//FilteredCertificates = null;
		return certs;
		
	
	} // end getCertificates
	
	/*
	* firma digital de los datos
	*/
	function signedData(datos)
	{
		// instantiate the CAPICOM objects
		var SignedData = new ActiveXObject("CAPICOM.SignedData");
		var Signer = new ActiveXObject("CAPICOM.Signer");
		var TimeAttribute = new ActiveXObject("CAPICOM.Attribute");
		
		// only do this if the user selected a certificate
		if (hash != "") {
			// Set the data that we want to sign
			SignedData.Content = datos;
			try {
				// Set the Certificate we would like to sign with
				//Signer.Certificate = SelectedCertificate.Item(1);
				Signer.Certificate = Certificate;
				
				// Set the time in which we are applying the signature
				var Today = new Date();
				TimeAttribute.Name = CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME;
				TimeAttribute.Value = Today.getVarDate();
				Today = null;
				Signer.AuthenticatedAttributes.Add(TimeAttribute);
				
				// Do the Sign operation
				var szSignature = SignedData.Sign(Signer, true, CAPICOM_ENCODE_BASE64);
				
			}catch (e) {
				if (e.number != CAPICOM_E_CANCELLED)
				{
					alert('Operación de firma cancelada' + ": " + e.message);
					return false;
				}
			} 
			return  szSignature;
		} else {
			alert('No se ha seleccionado un certificado válido');
			return false;
		}
	}
	
	function verifySignature(signature,datos) {
			try {
				var SignedData = new ActiveXObject("CAPICOM.SignedData");
				SignedData.Content=datos;
				SignedData.Verify(signature, true, CAPICOM_VERIFY_SIGNATURE_AND_CERTIFICATE);
				//alert('Firma Verificada'); 
				return true;
			} catch (e) {
			alert("ERROR : " + e.description);
			return false;
			}
	}
	
	function getCertificateBase64() {
		return Certificate.Export(CAPICOM_ENCODE_BASE64);
	}
}