import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import java.security.MessageDigest
import javax.crypto.BadPaddingException


fun main(){

    do {
        println("---EL CIFRADOR---")
        println("Introduce un mensaje: ")

        val mensaje = readLine()
        println("Clave de cifrado:")
        val llaveCifrado = readLine()

        if (mensaje != null && llaveCifrado != null) {
            val textCifrado = cifrar(mensaje, llaveCifrado)
            println("Clave de descifrado:")
            val llaveDescifrado = readLine()
            if (llaveDescifrado != null) {
                try {
                    val mensajeDescifrado = descifrar(textCifrado, llaveDescifrado)

                    if (mensaje.equals(mensajeDescifrado, true)) {
                        println("CIFRADO Y DECIFRADO COMPLETADO CON EXITO")
                    } else {
                        println("Fail")
                    }
                    println("\n")
                } catch (e : BadPaddingException) {
                    e.printStackTrace()
                    println("Fallo al descifrar")
                }

            }
        }

    } while(false)

}

private fun cifrar(textoEnString : String, llaveEnString : String) : String {
    println("Cifrando... $textoEnString")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, getKey(llaveEnString))
    val textCifrado = Base64.getEncoder().encodeToString(cipher.doFinal(textoEnString.toByteArray(Charsets.UTF_8)))
    println("Palabra cifrada como: $textCifrado")
    return textCifrado
}

@Throws(BadPaddingException::class)
private fun descifrar(textoCifrrado : String, llaveEnString : String) : String {
    println("Descifrando... $textoCifrrado")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, getKey(llaveEnString));
    val textDescifrado = String(cipher.doFinal(Base64.getDecoder().decode(textoCifrrado)))
    println("Texto descifrado: $textDescifrado")
    return textDescifrado
}


private fun getKey(llaveEnString : String): SecretKeySpec {
    var llaveUtf8 = llaveEnString.toByteArray(Charsets.UTF_8)
    val sha = MessageDigest.getInstance("SHA-1")
    llaveUtf8 = sha.digest(llaveUtf8)
    llaveUtf8 = llaveUtf8.copyOf(16)
    return SecretKeySpec(llaveUtf8, "AES")
}