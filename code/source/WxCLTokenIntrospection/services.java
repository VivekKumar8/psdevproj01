package WxCLTokenIntrospection;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
// --- <<IS-END-IMPORTS>> ---

public final class services

{
	// ---( internal utility methods )---

	final static services _instance = new services();

	static services _newInstance() { return new services(); }

	static services _cast(Object o) { return (services)o; }

	// ---( server methods )---




	public static final void verifyJWTToken (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(verifyJWTToken)>> ---
		// @sigtype java 3.5
		// [i] field:0:required token
		// [i] field:0:optional token_type_hint
		// [o] field:0:required active
		// [o] field:0:optional token_type
		// [o] field:0:optional client_id
		// [o] field:0:optional scope
		// [o] field:0:optional iat
		// [o] field:0:optional exp
		// pipeline
		IDataCursor pipelineCursor = pipeline.getCursor();
		String token = IDataUtil.getString(pipelineCursor, "token");
		String token_type_hint = IDataUtil.getString(pipelineCursor, "token_type_hint");
		String isActive = "false";
		pipelineCursor.destroy();
		DecodedJWT jwt = JWT.decode(token);
		try {
			//with ocl
			String rsaPublicKey = "-----BEGIN PUBLIC KEY-----"
					+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMoRUGknMri6dJczUp3A"
					+ "U/1voLvB6fi0IGVWi55uSsJCp+DxIHw3RZ4wZud0v48bX75k2kwJolK2jkDVMMwL"
					+ "qcdBJaRCT6RjCXbW1TEESEveuQyP1zSHD1l2B8XMWnRQKJ01pm5ARsJahbYc4sUJ"
					+ "xAX0Tgx6Tft9J/JWHskSzEINckuZn5PoG8gzwnROLaRUgRcwJ+vAJoSdBcM/xUD7"
					+ "/Qt92hcPseo8lgWHQONOlIH0TMZbzW41aVFeBmCbCmACP+9lSneNtPyOX0N3Jch6"
					+ "6BM+toJV4qpg7ElkMgnJvU9EKFl+6ZcWV7JpD2EDWUiyPqs0cuEGGYbP6K/PWQ5W"
					+ "wwIDAQAB"
					+ "-----END PUBLIC KEY-----";
			
			// without ocl
			/*
			 * String rsaPublicKey = "-----BEGIN PUBLIC KEY-----" +
			 * "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRCbA0OWBK5stX2j81EP" +
			 * "ot/+F7vpLbys0ErvwNZoygaPIkB6PEHruQ6Jvsi+9xZ3yaVmHJtvXsP7CgniHh25" +
			 * "LClT9jbVaLhCDc43mR8FJxpPgPF12bK9H7r1NlpwAKMchhmy/WNx1a1fctFF73iP" +
			 * "QU5gdTkloYDQPnNPQc2jqNU8u/gAvjb3BgZVmLNFOgsqCxWAvSRyn5qZITrpWNie" +
			 * "+bMZRYVzjsjS73ok4wR7FHt++162rVBXhWIEE4CKGaOwbRuNVJkK5Nz0u8dNyrdj" +
			 * "Kz6htcjl7zqWVLQctMDqFKiw2KHWQirpgZT7hx3ZZOoi5Nro0Xhqt5dqwtRkjVG6" +
			 * "BQIDAQAB" + "-----END PUBLIC KEY-----";
			 */
			
		
			rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
			rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey publicKey = kf.generatePublic(keySpec);
		
			Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
			algorithm.verify(jwt);
			// Check expiration
			if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
		
				throw new RuntimeException("Token Expired !");
			}
			isActive = "true";
			// pipeline
			IDataCursor pipelineCursor_1 = pipeline.getCursor();
			IDataUtil.put(pipelineCursor_1, "active", isActive);
			IDataUtil.put(pipelineCursor_1, "token_type", "Bearer");
			pipelineCursor_1.destroy();
		} /*
			 * catch(MalformedURLException mue){ throw new
			 * RuntimeException(mue.getMessage()); }catch (JwkException jwke) { throw new
			 * RuntimeException(jwke.getMessage()); }
			 */
		catch (IllegalArgumentException ilae) {
			throw new RuntimeException(ilae.getMessage());
		} catch (NoSuchAlgorithmException nsae) {
			throw new RuntimeException(nsae.getMessage());
		} catch (InvalidKeySpecException ikse) {
			throw new RuntimeException(ikse.getMessage());
		}
			
		// --- <<IS-END>> ---

                
	}
}

