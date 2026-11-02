//! Micro-Programmable 3D Graphics Mathematics & Shader Core for CorOS
//! 100% in-house implementation of vector algebra, affine transformations,
//! projection matrices, and programmable vertex/fragment lighting stages.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use crate::display::rasterizer::{Vec2, Vec3, Vec4, RasterVertex, sqrt_approx};

/// 3x3 Matrix for normal transformations and 2D affine operations
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mat3 {
    pub m: [f32; 9],
}

impl Mat3 {
    pub const IDENTITY: Self = Self {
        m: [
            1.0, 0.0, 0.0,
            0.0, 1.0, 0.0,
            0.0, 0.0, 1.0,
        ],
    };

    pub fn new(elements: [f32; 9]) -> Self {
        Self { m: elements }
    }

    pub fn transform_vec3(&self, v: Vec3) -> Vec3 {
        Vec3 {
            x: self.m[0] * v.x + self.m[1] * v.y + self.m[2] * v.z,
            y: self.m[3] * v.x + self.m[4] * v.y + self.m[5] * v.z,
            z: self.m[6] * v.x + self.m[7] * v.y + self.m[8] * v.z,
        }
    }
}

/// 4x4 Row-major Matrix for 3D homogeneous coordinate transformations
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mat4 {
    pub m: [f32; 16],
}

impl Mat4 {
    pub const IDENTITY: Self = Self {
        m: [
            1.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 1.0,
        ],
    };

    pub const ZERO: Self = Self {
        m: [0.0; 16],
    };

    pub fn new(elements: [f32; 16]) -> Self {
        Self { m: elements }
    }

    /// Multiply two 4x4 matrices (self * rhs)
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut out = [0.0f32; 16];
        for row in 0..4 {
            for col in 0..4 {
                let mut sum = 0.0;
                for k in 0..4 {
                    sum += self.m[row * 4 + k] * rhs.m[k * 4 + col];
                }
                out[row * 4 + col] = sum;
            }
        }
        Self { m: out }
    }

    /// Transform a 4D homogeneous vector (M * v)
    pub fn transform_vec4(&self, v: Vec4) -> Vec4 {
        Vec4 {
            x: self.m[0] * v.x + self.m[1] * v.y + self.m[2] * v.z + self.m[3] * v.w,
            y: self.m[4] * v.x + self.m[5] * v.y + self.m[6] * v.z + self.m[7] * v.w,
            z: self.m[8] * v.x + self.m[9] * v.y + self.m[10] * v.z + self.m[11] * v.w,
            w: self.m[12] * v.x + self.m[13] * v.y + self.m[14] * v.z + self.m[15] * v.w,
        }
    }

    /// Translation matrix
    pub fn translation(x: f32, y: f32, z: f32) -> Self {
        Self {
            m: [
                1.0, 0.0, 0.0, x,
                0.0, 1.0, 0.0, y,
                0.0, 0.0, 1.0, z,
                0.0, 0.0, 0.0, 1.0,
            ],
        }
    }

    /// Scale matrix
    pub fn scaling(sx: f32, sy: f32, sz: f32) -> Self {
        Self {
            m: [
                sx,  0.0, 0.0, 0.0,
                0.0, sy,  0.0, 0.0,
                0.0, 0.0, sz,  0.0,
                0.0, 0.0, 0.0, 1.0,
            ],
        }
    }

    /// Rotation around X-axis (angle in radians)
    pub fn rotation_x(rad: f32) -> Self {
        let (s, c) = sin_cos_approx(rad);
        Self {
            m: [
                1.0, 0.0, 0.0, 0.0,
                0.0, c,   -s,  0.0,
                0.0, s,   c,   0.0,
                0.0, 0.0, 0.0, 1.0,
            ],
        }
    }

    /// Rotation around Y-axis (angle in radians)
    pub fn rotation_y(rad: f32) -> Self {
        let (s, c) = sin_cos_approx(rad);
        Self {
            m: [
                c,   0.0, s,   0.0,
                0.0, 1.0, 0.0, 0.0,
                -s,  0.0, c,   0.0,
                0.0, 0.0, 0.0, 1.0,
            ],
        }
    }

    /// Rotation around Z-axis (angle in radians)
    pub fn rotation_z(rad: f32) -> Self {
        let (s, c) = sin_cos_approx(rad);
        Self {
            m: [
                c,   -s,  0.0, 0.0,
                s,   c,   0.0, 0.0,
                0.0, 0.0, 1.0, 0.0,
                0.0, 0.0, 0.0, 1.0,
            ],
        }
    }

    /// Creates a perspective projection matrix (FOV in radians, aspect ratio, near, far)
    pub fn perspective(fov_rad: f32, aspect: f32, near: f32, far: f32) -> Self {
        let tan_half_fov = tan_approx(fov_rad * 0.5);
        let f = if tan_half_fov.abs() > 0.0001 { 1.0 / tan_half_fov } else { 1.0 };
        let range = near - far;

        Self {
            m: [
                f / aspect, 0.0, 0.0, 0.0,
                0.0,        f,   0.0, 0.0,
                0.0,        0.0, (far + near) / range, (2.0 * far * near) / range,
                0.0,        0.0, -1.0, 0.0,
            ],
        }
    }

    /// Creates an orthographic projection matrix
    pub fn orthographic(left: f32, right: f32, bottom: f32, top: f32, near: f32, far: f32) -> Self {
        let w = right - left;
        let h = top - bottom;
        let d = far - near;

        Self {
            m: [
                2.0 / w, 0.0,     0.0,      -(right + left) / w,
                0.0,     2.0 / h, 0.0,      -(top + bottom) / h,
                0.0,     0.0,     -2.0 / d, -(far + near) / d,
                0.0,     0.0,     0.0,       1.0,
            ],
        }
    }

    /// Creates a camera LookAt view matrix
    pub fn look_at(eye: Vec3, target: Vec3, up: Vec3) -> Self {
        let f = Vec3::new(target.x - eye.x, target.y - eye.y, target.z - eye.z).normalize();
        let s = f.cross(up).normalize();
        let u = s.cross(f);

        let rot = Self {
            m: [
                s.x,  s.y,  s.z,  0.0,
                u.x,  u.y,  u.z,  0.0,
                -f.x, -f.y, -f.z, 0.0,
                0.0,  0.0,  0.0,  1.0,
            ],
        };

        let trans = Self::translation(-eye.x, -eye.y, -eye.z);
        rot.mul(&trans)
    }

    /// Computes the 3x3 normal matrix from the upper 3x3 model matrix
    pub fn to_normal_matrix(&self) -> Mat3 {
        // Upper 3x3
        let a = self.m[0];  let b = self.m[1];  let c = self.m[2];
        let d = self.m[4];  let e = self.m[5];  let f = self.m[6];
        let g = self.m[8];  let h = self.m[9];  let i = self.m[10];

        // Determinant of 3x3
        let det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
        if det.abs() < 0.000001 {
            return Mat3::IDENTITY;
        }
        let inv_det = 1.0 / det;

        // Inverse transpose of 3x3
        Mat3::new([
            (e * i - f * h) * inv_det,
            (c * h - b * i) * inv_det,
            (b * f - c * e) * inv_det,

            (f * g - d * i) * inv_det,
            (a * i - c * g) * inv_det,
            (c * d - a * f) * inv_det,

            (d * h - e * g) * inv_det,
            (g * b - a * h) * inv_det,
            (a * e - b * d) * inv_det,
        ])
    }
}

/// Fast Taylor approximation for sine and cosine in pure no_std
pub fn sin_cos_approx(rad: f32) -> (f32, f32) {
    const PI: f32 = 3.141592653589793;
    const TWO_PI: f32 = 6.283185307179586;

    // Normalize to -PI..PI
    let mut x = rad % TWO_PI;
    if x > PI {
        x -= TWO_PI;
    } else if x < -PI {
        x += TWO_PI;
    }

    // Taylor series for sin(x): x - x^3/6 + x^5/120 - x^7/5040
    let x2 = x * x;
    let x3 = x * x2;
    let x5 = x3 * x2;
    let x7 = x5 * x2;
    let sin = x - (x3 / 6.0) + (x5 / 120.0) - (x7 / 5040.0);

    // Taylor series for cos(x): 1 - x^2/2 + x^4/24 - x^6/720
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    let cos = 1.0 - (x2 / 2.0) + (x4 / 24.0) - (x6 / 720.0);

    (sin, cos)
}

/// Tangent approximation
pub fn tan_approx(rad: f32) -> f32 {
    let (s, c) = sin_cos_approx(rad);
    if c.abs() > 0.00001 {
        s / c
    } else {
        1.0
    }
}

/// Point Light representation
#[derive(Clone, Copy, Debug)]
pub struct PointLight {
    pub position: Vec3,
    pub color: Vec3,
    pub intensity: f32,
    pub constant_atten: f32,
    pub linear_atten: f32,
    pub quad_atten: f32,
}

impl PointLight {
    pub fn new(position: Vec3, color: Vec3, intensity: f32) -> Self {
        Self {
            position,
            color,
            intensity,
            constant_atten: 1.0,
            linear_atten: 0.09,
            quad_atten: 0.032,
        }
    }
}

/// Directional Sunlight representation
#[derive(Clone, Copy, Debug)]
pub struct DirectionalLight {
    pub direction: Vec3,
    pub color: Vec3,
    pub intensity: f32,
}

impl DirectionalLight {
    pub fn new(direction: Vec3, color: Vec3, intensity: f32) -> Self {
        Self {
            direction: direction.normalize(),
            color,
            intensity,
        }
    }
}

/// Material properties for Blinn-Phong shading
#[derive(Clone, Copy, Debug)]
pub struct Material {
    pub ambient: Vec3,
    pub diffuse: Vec3,
    pub specular: Vec3,
    pub shininess: f32,
}

impl Material {
    pub const DEFAULT: Self = Self {
        ambient: Vec3::new(0.2, 0.2, 0.2),
        diffuse: Vec3::new(0.8, 0.8, 0.8),
        specular: Vec3::new(1.0, 1.0, 1.0),
        shininess: 32.0,
    };
}

/// Raw 3D Vertex representation
#[derive(Clone, Copy, Debug)]
pub struct Vertex3D {
    pub pos: Vec3,
    pub uv: Vec2,
    pub normal: Vec3,
    pub color: Vec4,
}

impl Vertex3D {
    pub fn new(pos: Vec3, uv: Vec2, normal: Vec3, color: Vec4) -> Self {
        Self { pos, uv, normal, color }
    }
}

/// 3D Mesh buffer holding vertices and indices
pub struct Mesh3D {
    pub vertices: Vec<Vertex3D>,
    pub indices: Vec<u32>,
}

impl Mesh3D {
    pub fn new() -> Self {
        Self {
            vertices: Vec::new(),
            indices: Vec::new(),
        }
    }

    /// Generate a 3D unit cube (-0.5 to +0.5)
    pub fn create_cube() -> Self {
        let mut mesh = Self::new();
        let c = Vec4::new(1.0, 1.0, 1.0, 1.0);

        // Front face (Z = +0.5)
        let n = Vec3::new(0.0, 0.0, 1.0);
        let base = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, -0.5, 0.5), Vec2::new(0.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, -0.5, 0.5), Vec2::new(1.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, 0.5, 0.5), Vec2::new(1.0, 1.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, 0.5, 0.5), Vec2::new(0.0, 1.0), n, c));
        mesh.indices.extend_from_slice(&[base, base + 1, base + 2, base, base + 2, base + 3]);

        // Back face (Z = -0.5)
        let n = Vec3::new(0.0, 0.0, -1.0);
        let base = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, -0.5, -0.5), Vec2::new(0.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, -0.5, -0.5), Vec2::new(1.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, 0.5, -0.5), Vec2::new(1.0, 1.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, 0.5, -0.5), Vec2::new(0.0, 1.0), n, c));
        mesh.indices.extend_from_slice(&[base, base + 1, base + 2, base, base + 2, base + 3]);

        // Top face (Y = +0.5)
        let n = Vec3::new(0.0, 1.0, 0.0);
        let base = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, 0.5, 0.5), Vec2::new(0.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, 0.5, 0.5), Vec2::new(1.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, 0.5, -0.5), Vec2::new(1.0, 1.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, 0.5, -0.5), Vec2::new(0.0, 1.0), n, c));
        mesh.indices.extend_from_slice(&[base, base + 1, base + 2, base, base + 2, base + 3]);

        // Bottom face (Y = -0.5)
        let n = Vec3::new(0.0, -1.0, 0.0);
        let base = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, -0.5, -0.5), Vec2::new(0.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, -0.5, -0.5), Vec2::new(1.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, -0.5, 0.5), Vec2::new(1.0, 1.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, -0.5, 0.5), Vec2::new(0.0, 1.0), n, c));
        mesh.indices.extend_from_slice(&[base, base + 1, base + 2, base, base + 2, base + 3]);

        // Left face (X = -0.5)
        let n = Vec3::new(-1.0, 0.0, 0.0);
        let base = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, -0.5, -0.5), Vec2::new(0.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, -0.5, 0.5), Vec2::new(1.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, 0.5, 0.5), Vec2::new(1.0, 1.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(-0.5, 0.5, -0.5), Vec2::new(0.0, 1.0), n, c));
        mesh.indices.extend_from_slice(&[base, base + 1, base + 2, base, base + 2, base + 3]);

        // Right face (X = +0.5)
        let n = Vec3::new(1.0, 0.0, 0.0);
        let base = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, -0.5, 0.5), Vec2::new(0.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, -0.5, -0.5), Vec2::new(1.0, 0.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, 0.5, -0.5), Vec2::new(1.0, 1.0), n, c));
        mesh.vertices.push(Vertex3D::new(Vec3::new(0.5, 0.5, 0.5), Vec2::new(0.0, 1.0), n, c));
        mesh.indices.extend_from_slice(&[base, base + 1, base + 2, base, base + 2, base + 3]);

        mesh
    }

    /// Generate a 3D UV Sphere
    pub fn create_sphere(slices: usize, stacks: usize) -> Self {
        let mut mesh = Self::new();
        const PI: f32 = 3.14159265;
        let c = Vec4::new(0.9, 0.9, 0.9, 1.0);

        for stack in 0..=stacks {
            let phi = PI * (stack as f32 / stacks as f32);
            let (sin_phi, cos_phi) = sin_cos_approx(phi);

            for slice in 0..=slices {
                let theta = 2.0 * PI * (slice as f32 / slices as f32);
                let (sin_theta, cos_theta) = sin_cos_approx(theta);

                let x = cos_theta * sin_phi;
                let y = cos_phi;
                let z = sin_theta * sin_phi;

                let u = slice as f32 / slices as f32;
                let v = stack as f32 / stacks as f32;

                let normal = Vec3::new(x, y, z).normalize();
                mesh.vertices.push(Vertex3D::new(Vec3::new(x * 0.5, y * 0.5, z * 0.5), Vec2::new(u, v), normal, c));
            }
        }

        for stack in 0..stacks {
            for slice in 0..slices {
                let first = (stack * (slices + 1) + slice) as u32;
                let second = first + (slices as u32 + 1);

                mesh.indices.push(first);
                mesh.indices.push(second);
                mesh.indices.push(first + 1);

                mesh.indices.push(second);
                mesh.indices.push(second + 1);
                mesh.indices.push(first + 1);
            }
        }

        mesh
    }
}

/// 3D Graphics Pipeline Shader Execution Context
pub struct ShaderPipeline {
    pub model_matrix: Mat4,
    pub view_matrix: Mat4,
    pub proj_matrix: Mat4,
    pub normal_matrix: Mat3,
    pub dir_light: DirectionalLight,
    pub point_lights: Vec<PointLight>,
    pub camera_pos: Vec3,
    pub material: Material,
}

impl ShaderPipeline {
    pub fn new() -> Self {
        Self {
            model_matrix: Mat4::IDENTITY,
            view_matrix: Mat4::IDENTITY,
            proj_matrix: Mat4::IDENTITY,
            normal_matrix: Mat3::IDENTITY,
            dir_light: DirectionalLight::new(Vec3::new(0.5, 1.0, 0.5), Vec3::new(1.0, 1.0, 1.0), 1.0),
            point_lights: Vec::new(),
            camera_pos: Vec3::new(0.0, 0.0, 3.0),
            material: Material::DEFAULT,
        }
    }

    /// Update normal matrix whenever model matrix changes
    pub fn update_matrices(&mut self, model: Mat4, view: Mat4, proj: Mat4) {
        self.model_matrix = model;
        self.view_matrix = view;
        self.proj_matrix = proj;
        self.normal_matrix = model.to_normal_matrix();
    }

    /// Execute Vertex Shader stage: Model-View-Projection + Viewport mapping
    pub fn process_vertex(
        &self,
        vert: &Vertex3D,
        viewport_w: usize,
        viewport_h: usize,
    ) -> Option<RasterVertex> {
        let mvp = self.proj_matrix.mul(&self.view_matrix).mul(&self.model_matrix);
        let clip_pos = mvp.transform_vec4(Vec4::new(vert.pos.x, vert.pos.y, vert.pos.z, 1.0));

        // Near-plane clipping (W > 0.001)
        if clip_pos.w <= 0.001 {
            return None;
        }

        // Perspective divide to Normalized Device Coordinates (NDC: -1.0 to 1.0)
        let ndc_x = clip_pos.x / clip_pos.w;
        let ndc_y = clip_pos.y / clip_pos.w;
        let ndc_z = clip_pos.z / clip_pos.w;

        // Viewport transform to Screen Space
        let screen_x = (ndc_x + 1.0) * 0.5 * viewport_w as f32;
        let screen_y = (1.0 - ndc_y) * 0.5 * viewport_h as f32; // Invert Y for screen top-left
        let screen_z = (ndc_z + 1.0) * 0.5; // Depth mapped to 0.0..1.0

        // Normal transform for lighting
        let world_normal = self.normal_matrix.transform_vec3(vert.normal).normalize();

        // World space vertex position for light reflection
        let world_pos = self.model_matrix.transform_vec4(Vec4::new(vert.pos.x, vert.pos.y, vert.pos.z, 1.0));
        let world_vec = Vec3::new(world_pos.x, world_pos.y, world_pos.z);

        // Blinn-Phong lighting computation at vertex (Gouraud shading)
        let lit_color = self.compute_blinn_phong(world_vec, world_normal, vert.color);

        Some(RasterVertex {
            pos: Vec4::new(screen_x, screen_y, screen_z, clip_pos.w),
            uv: vert.uv,
            normal: world_normal,
            color: lit_color,
        })
    }

    /// Blinn-Phong lighting calculation
    fn compute_blinn_phong(&self, pos: Vec3, normal: Vec3, base_color: Vec4) -> Vec4 {
        // Ambient
        let mut final_r = self.material.ambient.x * base_color.x;
        let mut final_g = self.material.ambient.y * base_color.y;
        let mut final_b = self.material.ambient.z * base_color.z;

        // Directional Light
        let l_dir = self.dir_light.direction;
        let n_dot_l = normal.dot(l_dir).max(0.0);
        if n_dot_l > 0.0 {
            // Diffuse
            final_r += self.dir_light.color.x * self.material.diffuse.x * base_color.x * n_dot_l * self.dir_light.intensity;
            final_g += self.dir_light.color.y * self.material.diffuse.y * base_color.y * n_dot_l * self.dir_light.intensity;
            final_b += self.dir_light.color.z * self.material.diffuse.z * base_color.z * n_dot_l * self.dir_light.intensity;

            // Specular (Blinn-Phong half-angle vector)
            let view_dir = Vec3::new(self.camera_pos.x - pos.x, self.camera_pos.y - pos.y, self.camera_pos.z - pos.z).normalize();
            let half_dir = Vec3::new(l_dir.x + view_dir.x, l_dir.y + view_dir.y, l_dir.z + view_dir.z).normalize();
            let n_dot_h = normal.dot(half_dir).max(0.0);

            // Shininess power approximation
            let mut spec_factor = n_dot_h;
            for _ in 0..4 {
                spec_factor *= spec_factor; // ~16th power
            }

            final_r += self.dir_light.color.x * self.material.specular.x * spec_factor * self.dir_light.intensity;
            final_g += self.dir_light.color.y * self.material.specular.y * spec_factor * self.dir_light.intensity;
            final_b += self.dir_light.color.z * self.material.specular.z * spec_factor * self.dir_light.intensity;
        }

        // Point Lights
        for light in &self.point_lights {
            let l_vec = Vec3::new(light.position.x - pos.x, light.position.y - pos.y, light.position.z - pos.z);
            let dist = l_vec.length();
            if dist > 0.0001 {
                let l_dir = Vec3::new(l_vec.x / dist, l_vec.y / dist, l_vec.z / dist);
                let atten = 1.0 / (light.constant_atten + light.linear_atten * dist + light.quad_atten * dist * dist);

                let n_dot_l = normal.dot(l_dir).max(0.0);
                if n_dot_l > 0.0 {
                    final_r += light.color.x * self.material.diffuse.x * base_color.x * n_dot_l * atten * light.intensity;
                    final_g += light.color.y * self.material.diffuse.y * base_color.y * n_dot_l * atten * light.intensity;
                    final_b += light.color.z * self.material.diffuse.z * base_color.z * n_dot_l * atten * light.intensity;
                }
            }
        }

        Vec4::new(
            final_r.clamp(0.0, 1.0),
            final_g.clamp(0.0, 1.0),
            final_b.clamp(0.0, 1.0),
            base_color.w,
        )
    }
}
