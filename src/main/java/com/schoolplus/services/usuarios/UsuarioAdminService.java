package com.schoolplus.services.usuarios;

import com.schoolplus.model.EstadoUsuario;
import com.schoolplus.model.Rol;
import com.schoolplus.model.Usuario;
import com.schoolplus.repository.RolRepository;
import com.schoolplus.repository.UsuarioRepository;
import com.schoolplus.services.auth.ValidationService;
import com.schoolplus.services.password.PasswordResetService;
import com.schoolplus.util.UuidV7;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * El CRUD de usuarios que se opera desde el panel de administración: alta, edición,
 * activar o desactivar, y asignación de roles.
 *
 * <p><strong>No hay borrado físico.</strong> Un docente o estudiante tiene clases y
 * registros de asistencia que referencian su id; "eliminar" es pasar {@code estado} a
 * {@link EstadoUsuario#INACTIVO}. La persona conserva su historial y no puede volver a
 * entrar.</p>
 *
 * <p>Contraseña: el admin la fija al crear la cuenta, así nace usable aunque la persona
 * no revise el correo (un estudiante, un docente que nunca abrió el institucional). Al
 * editar es opcional: vacía deja la actual; si viene, pasa por la misma política que
 * cualquier otra y se cierran las sesiones abiertas de esa cuenta.</p>
 */
@Service
public class UsuarioAdminService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final ValidationService validationService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetService passwordService;

    public UsuarioAdminService(UsuarioRepository usuarioRepository,
                               RolRepository rolRepository,
                               ValidationService validationService,
                               PasswordEncoder passwordEncoder,
                               PasswordResetService passwordService) {
        this.usuarioRepository = usuarioRepository;
        this.rolRepository = rolRepository;
        this.validationService = validationService;
        this.passwordEncoder = passwordEncoder;
        this.passwordService = passwordService;
    }

    /**
     * Alta con contraseña obligatoria. Sus errores salen junto con los del resto del
     * formulario: o se crea la cuenta completa o no se crea.
     */
    @Transactional
    public Usuario crear(DatosUsuario datos, String password, String confirmacion) {
        List<String> errores = validarBasicos(datos);
        errores.addAll(validationService.validarPassword(password, confirmacion, datos.nombre(), datos.email()));
        if (usuarioRepository.existsByEmail(datos.email())) {
            errores.add("Ese correo ya tiene cuenta.");
        }
        if (usuarioRepository.existsByCedula(datos.cedula())) {
            errores.add("Esa cédula ya está registrada.");
        }
        if (!errores.isEmpty()) {
            throw new DatosUsuarioInvalidosException(errores);
        }

        Usuario usuario = new Usuario();
        usuario.setId(UuidV7.nuevoId());
        usuario.setEstado(EstadoUsuario.ACTIVO);
        aplicarDatos(usuario, datos);
        usuario.setPasswordHash(passwordEncoder.encode(password));

        // Rol base: igual que el auto-registro, nadie nace con permisos elevados por
        // defecto. Se suben aparte con asignarRoles, un acto deliberado.
        Rol rolBase = rolRepository.findById(Rol.USUARIO).orElseThrow(() ->
                new IllegalStateException("Falta el rol USUARIO. ¿Se aplicó la migración V1?"));
        usuario.getRoles().add(rolBase);

        return usuarioRepository.save(usuario);
    }

    /** Edición. {@code password} vacía o nula deja la contraseña actual intacta. */
    @Transactional
    public Usuario actualizar(String usuarioId, DatosUsuario datos, String password, String confirmacion) {
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new IllegalArgumentException("El usuario " + usuarioId + " no existe."));

        List<String> errores = validarBasicos(datos);
        usuarioRepository.findByEmail(datos.email())
                .filter(otro -> !otro.getId().equals(usuarioId))
                .ifPresent(otro -> errores.add("Ese correo ya tiene cuenta."));
        usuarioRepository.findByCedula(datos.cedula())
                .filter(otro -> !otro.getId().equals(usuarioId))
                .ifPresent(otro -> errores.add("Esa cédula ya está registrada."));
        boolean cambiaPassword = password != null && !password.isEmpty();
        if (cambiaPassword) {
            errores.addAll(validationService.validarPassword(password, confirmacion, datos.nombre(), datos.email()));
        }
        if (!errores.isEmpty()) {
            throw new DatosUsuarioInvalidosException(errores);
        }

        // Las sesiones abiertas están a nombre del correo de antes, por si también cambia.
        String emailAnterior = usuario.getEmail();
        aplicarDatos(usuario, datos);
        if (cambiaPassword) {
            usuario.setPasswordHash(passwordEncoder.encode(password));
        }
        Usuario guardado = usuarioRepository.save(usuario);
        if (cambiaPassword) {
            passwordService.cerrarSesionesDe(emailAnterior);
        }
        return guardado;
    }

    @Transactional
    public void cambiarEstado(String usuarioId, EstadoUsuario nuevoEstado) {
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new IllegalArgumentException("El usuario " + usuarioId + " no existe."));
        usuario.setEstado(nuevoEstado);
        usuarioRepository.save(usuario);
    }

    /** Reemplaza el conjunto completo de roles. Vacío deja al usuario sin ninguno. */
    @Transactional
    public void asignarRoles(String usuarioId, Set<String> codigosRol) {
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new IllegalArgumentException("El usuario " + usuarioId + " no existe."));

        List<Rol> roles = rolRepository.findAllById(codigosRol);
        if (roles.size() != codigosRol.size()) {
            Set<String> encontrados = roles.stream().map(Rol::getCodigo).collect(Collectors.toSet());
            List<String> faltantes = codigosRol.stream().filter(c -> !encontrados.contains(c)).toList();
            throw new IllegalArgumentException("Rol inexistente: " + String.join(", ", faltantes));
        }

        usuario.getRoles().clear();
        usuario.getRoles().addAll(roles);
        usuarioRepository.save(usuario);
    }

    // ── Interno ──────────────────────────────────────────────────────────────

    private List<String> validarBasicos(DatosUsuario datos) {
        return new ArrayList<>(validationService.validarDatosBasicos(
                datos.nombre(), datos.email(), datos.cedula(), datos.telefono()));
    }

    private void aplicarDatos(Usuario usuario, DatosUsuario datos) {
        usuario.setNombre(datos.nombre().trim().replaceAll("\s+", " "));
        usuario.setEmail(datos.email().trim().toLowerCase());
        usuario.setCedula(datos.cedula().trim());
        usuario.setTelefono(datos.telefono().trim());
        usuario.setFechaNacimiento(datos.fechaNacimiento());
    }
}
