// server.js - versão corrigida e segura
import 'dotenv/config';
import express from 'express';
import { createPool } from 'mysql2';
import cors from 'cors';
import pkg from 'body-parser';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const { json } = pkg;
const app = express();

// ======================
// MIDDLEWARES DE SEGURANÇA
// ======================

app.use(helmet());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://10.0.2.2:3000',
    'https://taskflow-api-055k.onrender.com' // sua URL do Render
  ],
  credentials: true
}));
app.use(json());
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 requests por IP
  message: { error: 'Muitas requisições deste IP, tente novamente mais tarde.' }
});
app.use('/login', limiter);
app.use('/clientes', limiter);

// ======================
// CONFIGURAÇÕES
// ======================

// Configuração Multer melhorada
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas imagens são permitidas!'), false);
    }
  }
});

// Servir arquivos da pasta uploads
app.use('/uploads', express.static('uploads'));

// ======================
// VALIDAÇÃO ENV
// ======================

const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME'];
const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missing.length > 0) {
  console.error('❌ Variáveis de ambiente faltando:', missing);
  process.exit(1);
}

// ======================
// CONEXÃO COM BANCO (COM POOL)
// ======================

const pool = createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT || '4000', 10),
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: true } : undefined,
  connectionLimit: 10,
});

// Testar conexão
pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Erro ao conectar ao banco:', err.message);
    process.exit(1);
  } else {
    console.log('✅ Conectado ao banco de dados com pool');
    connection.release();
  }
});

const dbPromise = pool.promise();

// ======================
// MIDDLEWARE DE ERRO
// ======================

app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);

  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Arquivo muito grande. Tamanho máximo: 5MB' });
    }
    return res.status(400).json({ error: 'Erro no upload de arquivo' });
  }

  res.status(500).json({
    error: 'Erro interno do servidor',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// ======================
// ROTAS
// ======================

/* ---------------------------
   Rota: cadastrar cliente - ATUALIZADA
----------------------------*/
app.post('/clientes', async (req, res) => {
  try {
    const { Nome, Email, Senha, Perfil_Acesso } = req.body; // ✅ RECEBER PERFIL_ACESSO

    if (!Nome || !Email || !Senha) {
      return res.status(400).json({ error: 'Nome, Email e Senha são obrigatórios.' });
    }

    // Validar email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(Email)) {
      return res.status(400).json({ error: 'Email inválido.' });
    }

    // ✅ DEFINIR PERFIL PADRÃO SE NÃO ENVIADO
    const perfilAcesso = Perfil_Acesso || 'Usuario';

    // Verificar se email já existe (case insensitive)
    const [exists] = await dbPromise.query(
      'SELECT 1 FROM CLIENTES WHERE LOWER(Email) = LOWER(?) LIMIT 1',
      [Email.trim()]
    );

    if (exists.length > 0) {
      return res.status(409).json({ error: 'Email já cadastrado' });
    }

    // Hash da senha
    const saltRounds = 12;
    const senhaHash = await bcrypt.hash(Senha, saltRounds);

    // ✅ ATUALIZAR QUERY PARA INCLUIR PERFIL_ACESSO
    const [result] = await dbPromise.query(
      'INSERT INTO CLIENTES (Nome, Email, Senha_hash, Perfil_Acesso) VALUES (?, ?, ?, ?)',
      [Nome.trim(), Email.trim().toLowerCase(), senhaHash, perfilAcesso] // ✅ ADICIONAR PERFIL
    );

    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso',
      id: result.insertId
    });

  } catch (err) {
    console.error('[POST /clientes] erro:', err.message);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: login
----------------------------*/
app.post('/login', async (req, res) => {
  try {
    const { Email, Senha } = req.body;
    console.log('🔐 Login attempt for:', Email);

    if (!Email || !Senha) {
      return res.status(400).json({ error: 'Email e Senha são obrigatórios.' });
    }

    // ✅ BUSCAR USUÁRIO ATIVO
    const [rows] = await dbPromise.query(
      'SELECT ID_CLIENTE, Nome, Email, Senha_hash, Perfil_Acesso FROM CLIENTES WHERE LOWER(Email) = LOWER(?) AND Ativo = 1 LIMIT 1',
      [Email.trim()]
    );

    console.log('📊 User found:', rows[0]); // ✅ DEBUG

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }

    const user = rows[0];

    // Verificar senha
    const senhaValida = await bcrypt.compare(Senha, user.Senha_hash);

    if (!senhaValida) {
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }

    // ✅ DEBUG: Verificar o que está sendo retornado
    console.log('🎯 Returning user data:', {
      ID_CLIENTE: user.ID_CLIENTE,
      Nome: user.Nome,
      Email: user.Email,
      Perfil_Acesso: user.Perfil_Acesso
    });

    return res.json({
      message: 'Login realizado com sucesso',
      usuario: {
        ID_CLIENTE: user.ID_CLIENTE,
        Nome: user.Nome,
        Email: user.Email,
        Perfil_Acesso: user.Perfil_Acesso
      }
    });

  } catch (err) {
    console.error('[POST /login] erro:', err.message);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: listar usuários
----------------------------*/
app.get('/usuarios', async (req, res) => {
  try {
    // ✅ LISTAR APENAS USUÁRIOS ATIVOS
    const [rows] = await dbPromise.query(
      'SELECT ID_CLIENTE, Nome FROM CLIENTES WHERE Ativo = 1 ORDER BY Nome'
    );
    const mapped = rows.map(r => ({ id: r.ID_CLIENTE, nome: r.Nome }));
    res.json(mapped);
  } catch (err) {
    console.error('[GET /usuarios] erro:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: listar setores
----------------------------*/
app.get('/setores', async (req, res) => {
  try {
    // ✅ LISTAR APENAS SETORES ATIVOS
    const [rows] = await dbPromise.query(
      'SELECT ID_Setor, Nome FROM SETORES WHERE Ativo = 1 ORDER BY Nome'
    );
    const mapped = rows.map(r => ({ id: r.ID_Setor, nome: r.Nome }));
    res.json(mapped);
  } catch (err) {
    console.error('[GET /setores] erro:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: ticket metadata
----------------------------*/
app.get('/ticket-metadata', (req, res) => {
  res.json({
    statuses: ['Aberto', 'Em Andamento', 'Fechado'],
    priorities: ['Baixa', 'Média', 'Alta']
  });
});

/* ---------------------------
   Rota: listar tickets (CHAMADOS) - CORRIGIDA COM FILTROS
----------------------------*/
app.get('/tickets', async (req, res) => {
    try {
        const { status, priority, user, sector, limit, offset } = req.query;

        console.log('🔍 Filtros recebidos:', {
            status, priority, user, sector, limit, offset
        });

        let sql = `
            SELECT
                t.ID_CHAMADO AS ID_Ticket,
                t.Titulo,
                t.Descricao,
                t.ChamadoStatus AS TicketStatus,
                t.Data_Abertura,
                t.Data_Fechamento,
                t.Prioridade,
                t.ID_CLIENTE AS ID_Cliente,
                t.ID_SETOR AS ID_Setor,
                c.Nome AS ClienteNome,
                s.Nome AS SetorNome,
                t.Imagem,
                t.Tecnico
            FROM CHAMADOS t
            LEFT JOIN SETORES s ON t.ID_SETOR = s.ID_Setor
            LEFT JOIN CLIENTES c ON t.ID_CLIENTE = c.ID_CLIENTE
            WHERE 1=1
        `;

        const params = [];

        // ✅✅✅ FILTRO DE STATUS - CORRIGIDO
        if (status && status !== 'null' && status !== 'Status') {
            sql += ' AND t.ChamadoStatus = ?';
            params.push(status);
            console.log('✅ Aplicando filtro status:', status);
        }

        // ✅✅✅ FILTRO DE PRIORIDADE - CORRIGIDO
        if (priority && priority !== 'null' && priority !== 'Prioridade') {
            sql += ' AND t.Prioridade = ?';
            params.push(priority);
            console.log('✅ Aplicando filtro prioridade:', priority);
        }

        // ✅✅✅ FILTRO DE USUÁRIO - CORRIGIDO
        if (user && user !== 'null' && user !== '0') {
            sql += ' AND t.ID_CLIENTE = ?';
            params.push(parseInt(user, 10));
            console.log('✅ Aplicando filtro usuário:', user);
        }

        // ✅✅✅ FILTRO DE SETOR - CORRIGIDO
        if (sector && sector !== 'null' && sector !== '0') {
            sql += ' AND t.ID_SETOR = ?';
            params.push(parseInt(sector, 10));
            console.log('✅ Aplicando filtro setor:', sector);
        }

        // ✅✅✅ ORDENAÇÃO CORRETA - MAIS RECENTES PRIMEIRO
        sql += ' ORDER BY t.Data_Abertura DESC';

        // ✅✅✅ PAGINAÇÃO SEGURA
        const safeLimit = Math.min(parseInt(limit, 10) || 50, 100);
        const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

        sql += ' LIMIT ? OFFSET ?';
        params.push(safeLimit, safeOffset);

        console.log('📋 SQL final:', sql);
        console.log('🔢 Parâmetros:', params);

        const [rows] = await dbPromise.query(sql, params);

        console.log('🎫 Tickets encontrados:', rows.length);

        const mapped = rows.map(r => {
            // ✅ PROCESSAR IMAGENS CORRETAMENTE NA LISTA
            let imagens = [];
            if (r.Imagem) {
                if (r.Imagem.includes(',')) {
                    // Múltiplas imagens
                    const imageArray = r.Imagem.split(',').map(img => img.trim());
                    imagens = imageArray.map(img => `/uploads/${img}`);
                } else {
                    // Imagem única
                    const imagemUnica = r.Imagem.trim();
                    if (imagemUnica && imagemUnica !== 'null') {
                        imagens = [`/uploads/${imagemUnica}`];
                    }
                }
            }

            return {
                ID_Ticket: r.ID_Ticket,
                Titulo: r.Titulo,
                Descricao: r.Descricao,
                TicketStatus: r.TicketStatus,
                Data_Abertura: r.Data_Abertura,
                Data_Fechamento: r.Data_Fechamento,
                Prioridade: r.Prioridade,
                ID_Cliente: r.ID_Cliente != null ? String(r.ID_Cliente) : null,
                ID_Setor: r.ID_Setor,
                ClienteNome: r.ClienteNome,
                SetorNome: r.SetorNome,
                Tecnico: r.Tecnico,
                Imagem: imagens.length > 0 ? imagens[0] : null,
                Imagens: imagens
            };
        });

        res.json(mapped);

    } catch (err) {
        console.error('[GET /tickets] erro:', err.message);
        res.status(500).json({ error: 'Erro interno: ' + err.message });
    }
});

/* ---------------------------
   Rota: criar ticket com MÚLTIPLAS imagens - PADRONIZADA
----------------------------*/
app.post('/tickets', upload.array('Imagens', 5), async (req, res) => {
    try {
        console.log('🎯 NOVO TICKET - INICIANDO PROCESSAMENTO');
        console.log('📦 Dados recebidos:', req.body);
        console.log('🖼️ Arquivos recebidos:', req.files ? req.files.length : 0);

        // ✅ LOG DETALHADO DOS ARQUIVOS
        if (req.files && req.files.length > 0) {
            req.files.forEach((file, index) => {
                console.log(`📄 Arquivo ${index + 1}:`, {
                    nome_original: file.originalname,
                    tamanho: file.size,
                    mimetype: file.mimetype,
                    campo: file.fieldname
                });
            });
        }

        const { Titulo, Descricao, Prioridade, ID_Cliente, Nome_Cliente, ID_Setor } = req.body;

        // ✅ VALIDAÇÃO DOS CAMPOS OBRIGATÓRIOS
        if (!Titulo || !Descricao || !Prioridade || !ID_Cliente || !Nome_Cliente) {
            console.log('❌ Campos obrigatórios faltando:', {
                Titulo: !!Titulo,
                Descricao: !!Descricao,
                Prioridade: !!Prioridade,
                ID_Cliente: !!ID_Cliente,
                Nome_Cliente: !!Nome_Cliente
            });
            return res.status(400).json({ error: 'Título, Descrição, Prioridade e Cliente são obrigatórios.' });
        }

        // ✅ VALIDAR PRIORIDADE
        if (!['Baixa', 'Média', 'Alta'].includes(Prioridade)) {
            console.log('❌ Prioridade inválida:', Prioridade);
            return res.status(400).json({ error: 'Prioridade inválida. Use: Baixa, Média ou Alta' });
        }

        const dataAbertura = new Date();
        console.log('📅 Data de abertura:', dataAbertura);

        // ✅ PROCESSAR MÚLTIPLAS IMAGENS COM PADRONIZAÇÃO OBRIGATÓRIA
        let imagensPaths = [];
        if (req.files && req.files.length > 0) {
            const uploadDir = path.join(process.cwd(), 'uploads');
            
            // ✅ GARANTIR QUE A PASTA UPLOADS EXISTE
            if (!fs.existsSync(uploadDir)) {
                console.log('📁 Criando pasta uploads...');
                fs.mkdirSync(uploadDir, { recursive: true });
            }
            
            console.log('💾 Iniciando salvamento de imagens...');
            
            for (let i = 0; i < req.files.length; i++) {
                const file = req.files[i];
                const nomeOriginal = file.originalname;
                
                console.log(`🔄 Processando imagem ${i + 1}: ${nomeOriginal}`);

                // ✅ PADRONIZAÇÃO OBRIGATÓRIA - SEMPRE GERAR NOME NOVO
                const extensao = path.extname(nomeOriginal) || '.jpg';
                
                // Gerar nome completamente novo e padronizado
                const timestamp = Date.now();
                const randomStr = Math.random().toString(36).substring(2, 9); // 7 caracteres aleatórios
                const fileName = `img_${timestamp}_${randomStr}${extensao.toLowerCase()}`;
                
                const filePath = path.join(uploadDir, fileName);
                
                try {
                    // ✅ SALVAR ARQUIVO NO SERVIDOR
                    fs.writeFileSync(filePath, file.buffer);
                    imagensPaths.push(fileName);
                    
                    console.log('✅ Imagem salva com sucesso:', {
                        nome_original: nomeOriginal,
                        nome_padronizado: fileName,
                        tamanho: file.size,
                        caminho: filePath
                    });
                    
                } catch (fileError) {
                    console.error(`❌ Erro ao salvar imagem ${i + 1}:`, fileError.message);
                    // Continua processando outras imagens mesmo se uma falhar
                }
            }
            
            console.log(`🎉 Total de imagens processadas: ${imagensPaths.length}/${req.files.length}`);
        } else {
            console.log('ℹ️ Nenhuma imagem para processar');
        }

        console.log('📋 Imagens a serem salvas no banco:', imagensPaths);

        // ✅ VALIDAR E CONVERTER IDs
        const idClienteNum = parseInt(ID_Cliente, 10);
        const idSetorNum = ID_Setor ? parseInt(ID_Setor, 10) : null;

        if (isNaN(idClienteNum)) {
            console.log('❌ ID_Cliente inválido:', ID_Cliente);
            return res.status(400).json({ error: 'ID_Cliente inválido' });
        }

        if (ID_Setor && isNaN(idSetorNum)) {
            console.log('❌ ID_Setor inválido:', ID_Setor);
            return res.status(400).json({ error: 'ID_Setor inválido' });
        }

        // ✅ INSERIR TICKET NO BANCO DE DADOS
        console.log('💾 Inserindo ticket no banco de dados...');
        
        const [result] = await dbPromise.query(
            `INSERT INTO CHAMADOS 
             (Titulo, Descricao, ChamadoStatus, Data_Abertura, Data_Fechamento, Prioridade, ID_CLIENTE, Nome_Cliente, ID_SETOR, Imagem)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                Titulo.trim(),
                Descricao.trim(),
                'Aberto', // Status padrão
                dataAbertura,
                null, // Data_Fechamento inicialmente nula
                Prioridade,
                idClienteNum,
                Nome_Cliente.trim(),
                idSetorNum,
                imagensPaths.length > 0 ? imagensPaths.join(',') : null // Salva como string separada por vírgulas
            ]
        );

        const ticketId = result.insertId;
        console.log('✅ Ticket criado no banco com ID:', ticketId);

        // ✅ BUSCAR TICKET CRIADO PARA RETORNO COMPLETO
        console.log('🔍 Buscando dados completos do ticket...');
        const [rows] = await dbPromise.query(
            `SELECT
                 t.ID_CHAMADO AS ID_Ticket,
                 t.Titulo,
                 t.Descricao,
                 t.ChamadoStatus AS TicketStatus,
                 t.Data_Abertura,
                 t.Data_Fechamento,
                 t.Prioridade,
                 t.ID_CLIENTE AS ID_Cliente,
                 t.ID_SETOR AS ID_Setor,
                 t.Nome_Cliente AS ClienteNome,
                 s.Nome AS SetorNome,
                 t.Imagem,
                 t.Tecnico
               FROM CHAMADOS t
               LEFT JOIN SETORES s ON t.ID_SETOR = s.ID_Setor
               WHERE t.ID_CHAMADO = ?`,
            [ticketId]
        );

        if (rows.length === 0) {
            console.error('❌ Ticket não encontrado após criação. ID:', ticketId);
            return res.status(500).json({ error: 'Erro ao recuperar ticket criado' });
        }

        const ticket = rows[0];
        
        // ✅ FORMATAR IMAGENS PARA RETORNO
        if (ticket.Imagem) {
            const imageArray = ticket.Imagem.split(',');
            ticket.Imagens = imageArray.map(img => `/uploads/${img}`);
        } else {
            ticket.Imagens = [];
        }

        console.log('🎉 Ticket criado com sucesso:', {
            id: ticket.ID_Ticket,
            titulo: ticket.Titulo,
            cliente: ticket.ClienteNome,
            setor: ticket.SetorNome,
            prioridade: ticket.Prioridade,
            total_imagens: ticket.Imagens.length,
            nomes_imagens: ticket.Imagem
        });

        // ✅ RETORNAR RESPOSTA DE SUCESSO
        res.status(201).json({
            message: 'Ticket criado com sucesso',
            ticket: ticket
        });

    } catch (err) {
        console.error('💥 [POST /tickets] ERRO CRÍTICO:', err.message);
        console.error('Stack trace:', err.stack);
        
        res.status(500).json({ 
            error: 'Erro interno do servidor',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

/* ---------------------------
   Rota: buscar ticket por ID - CORRIGIDA
----------------------------*/
app.get('/tickets/:id', async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id, 10);

        if (isNaN(ticketId) || ticketId <= 0) {
            return res.status(400).json({ error: 'ID do ticket inválido' });
        }

        const [rows] = await dbPromise.query(
            `SELECT
                t.ID_CHAMADO AS ID_Ticket,
                t.Titulo,
                t.Descricao,
                t.ChamadoStatus AS TicketStatus,
                t.Data_Abertura,
                t.Data_Fechamento,
                t.Prioridade,
                t.ID_CLIENTE AS ID_Cliente,
                t.ID_SETOR AS ID_Setor,
                c.Nome AS ClienteNome,
                s.Nome AS SetorNome,
                t.Imagem,
                t.Tecnico
            FROM CHAMADOS t
            LEFT JOIN SETORES s ON t.ID_SETOR = s.ID_Setor
            LEFT JOIN CLIENTES c ON t.ID_CLIENTE = c.ID_CLIENTE
            WHERE t.ID_CHAMADO = ?`,
            [ticketId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Ticket não encontrado' });
        }

        const ticket = rows[0];
        
        // ✅✅✅ FORMATAR IMAGENS CORRETAMENTE - VERSÃO MELHORADA
        if (ticket.Imagem) {
            // Se a imagem está salva como string separada por vírgulas
            if (ticket.Imagem.includes(',')) {
                const imageArray = ticket.Imagem.split(',').map(img => img.trim());
                ticket.Imagens = imageArray.map(img => `/uploads/${img}`);
                ticket.Imagem = null; // Limpar o campo antigo
            } else {
                // Imagem única
                const imagemUnica = ticket.Imagem.trim();
                if (imagemUnica && imagemUnica !== 'null') {
                    ticket.Imagem = `/uploads/${imagemUnica}`;
                    ticket.Imagens = [ticket.Imagem];
                } else {
                    ticket.Imagem = null;
                    ticket.Imagens = [];
                }
            }
        } else {
            ticket.Imagens = [];
        }

        console.log('🎫 Ticket retornado:', {
            id: ticket.ID_Ticket,
            titulo: ticket.Titulo,
            totalImagens: ticket.Imagens ? ticket.Imagens.length : 0,
            imagens: ticket.Imagens
        });

        res.json(ticket);
    } catch (err) {
        console.error('[GET /tickets/:id] erro:', err.message);
        res.status(500).json({ error: 'Erro interno' });
    }
});

/* ---------------------------
   Rota: atualizar ticket (VERSÃO CORRIGIDA - permite técnicos)
----------------------------*/
app.put('/tickets/:id', async (req, res) => {
  try {
    const ticketId = parseInt(req.params.id, 10);
    const { Titulo, Descricao, Prioridade, ID_Setor, TicketStatus, ID_Cliente, Tecnico } = req.body;

    console.log('🔧 [PUT /tickets] Dados recebidos:', {
      ticketId, Titulo, Descricao, Prioridade, ID_Setor, TicketStatus, ID_Cliente, Tecnico
    });

    // ✅ VALIDAÇÃO ATUALIZADA - ID_Cliente não é mais obrigatório para técnicos
    if (!Titulo || !Descricao || !Prioridade || !ID_Setor) {
      return res.status(400).json({ error: 'Campos obrigatórios: Titulo, Descricao, Prioridade, ID_Setor' });
    }

    // Verificar se ticket existe
    const [ticketRows] = await dbPromise.query(
      'SELECT ID_CLIENTE, ChamadoStatus, Data_Fechamento FROM CHAMADOS WHERE ID_CHAMADO = ?',
      [ticketId]
    );

    if (ticketRows.length === 0) {
      return res.status(404).json({ error: 'Ticket não encontrado.' });
    }

    const ticket = ticketRows[0];
    
    // ✅ BUSCAR PERFIL DO USUÁRIO QUE ESTÁ EDITANDO
    const [userRows] = await dbPromise.query(
      'SELECT Perfil_Acesso, Nome FROM CLIENTES WHERE ID_CLIENTE = ?',
      [ID_Cliente]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const userPerfil = userRows[0].Perfil_Acesso;
    const userName = userRows[0].Nome;

    console.log('🔧 [PUT /tickets] Perfil do usuário:', userPerfil, 'Nome:', userName);

    // ✅ LÓGICA DE PERMISSÃO ATUALIZADA
    let tecnicoParaSalvar = Tecnico;
    
    // Se for técnico/admin, permitir editar qualquer ticket
    if (userPerfil === 'Tecnico' || userPerfil === 'Admin') {
      console.log('✅ Usuário é técnico/admin - permitindo edição');
      // Se não foi enviado técnico, usar o nome do usuário logado
      if (!tecnicoParaSalvar) {
        tecnicoParaSalvar = userName;
      }
    } else {
      // Se for usuário comum, verificar se é o dono do ticket
      console.log('🔍 Usuário comum - verificando propriedade');
      if (String(ticket.ID_CLIENTE) !== String(ID_Cliente)) {
        return res.status(403).json({ error: 'Você não tem permissão para editar este ticket.' });
      }
      // Usuários comuns não podem definir técnico
      tecnicoParaSalvar = null;
    }

    // Se TicketStatus não foi enviado, mantém o status atual
    const novoStatus = TicketStatus || ticket.ChamadoStatus;

    // ✅ LÓGICA PARA DATA_FECHAMENTO AUTOMÁTICA (CORRIGIDA)
    let dataFechamento = ticket.Data_Fechamento; // Mantém a data atual se existir

    if (novoStatus === 'Fechado' && ticket.ChamadoStatus !== 'Fechado') {
      // Se está fechando o ticket AGORA (não estava fechado antes)
      dataFechamento = new Date();
      console.log('🔒 Fechando ticket - Data_Fechamento:', dataFechamento);
    } else if (novoStatus !== 'Fechado' && ticket.ChamadoStatus === 'Fechado') {
      // Se está reabrindo um ticket que estava fechado
      dataFechamento = null;
      console.log('🔓 Reabrindo ticket - Data_Fechamento removida');
    }

    console.log('💾 Salvando com técnico:', tecnicoParaSalvar, 'Status:', novoStatus, 'Data_Fechamento:', dataFechamento);

    // ✅ ATUALIZAR COM DATA_FECHAMENTO AUTOMÁTICA (F MAIÚSCULO CORRETO)
    await dbPromise.query(
      `UPDATE CHAMADOS 
       SET Titulo = ?, Descricao = ?, Prioridade = ?, ID_SETOR = ?, ChamadoStatus = ?, Tecnico = ?, Data_Fechamento = ?
       WHERE ID_CHAMADO = ?`,
      [Titulo, Descricao, Prioridade, ID_Setor, novoStatus, tecnicoParaSalvar, dataFechamento, ticketId]
    );

    res.json({ message: 'Ticket atualizado com sucesso' });

  } catch (err) {
    console.error('[PUT /tickets/:id] erro:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: recuperar senha
----------------------------*/
app.post('/recuperar-senha', async (req, res) => {
  try {
    const { Email } = req.body;

    if (!Email) {
      return res.status(400).json({ error: 'Email é obrigatório' });
    }

    // Verificar se email existe
    const [rows] = await dbPromise.query(
      'SELECT ID_CLIENTE, Nome FROM CLIENTES WHERE Email = ? LIMIT 1',
      [Email]
    );

    if (rows.length === 0) {
      // Por segurança, não revelar que email não existe
      return res.json({ message: 'Se o email existir, enviaremos instruções' });
    }

    // Aqui você implementaria:
    // 1. Gerar token de recuperação
    // 2. Salvar token no banco com expiração
    // 3. Enviar email com link de recuperação

    return res.json({
      message: 'Instruções de recuperação enviadas para seu email'
    });

  } catch (err) {
    console.error('[POST /recuperar-senha] erro:', err.message);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: atualizar perfil do usuário
----------------------------*/
app.put('/atualizar-perfil', async (req, res) => {
  try {
    const { ID_CLIENTE, Nome, Email, Senha } = req.body;

    if (!ID_CLIENTE || !Nome || !Email) {
      return res.status(400).json({ error: 'ID_CLIENTE, Nome e Email são obrigatórios' });
    }

    // Verificar se email já existe (para outro usuário)
    const [emailExists] = await dbPromise.query(
      'SELECT ID_CLIENTE FROM CLIENTES WHERE Email = ? AND ID_CLIENTE != ?',
      [Email, ID_CLIENTE]
    );

    if (emailExists.length > 0) {
      return res.status(409).json({ error: 'Email já está em uso por outro usuário' });
    }

    let query, params;

    // Se senha foi fornecida, atualiza com senha
    if (Senha && Senha.trim() !== '') {
      const senhaHash = await bcrypt.hash(Senha, 12);
      query = 'UPDATE CLIENTES SET Nome = ?, Email = ?, Senha_hash = ? WHERE ID_CLIENTE = ?';
      params = [Nome, Email, senhaHash, ID_CLIENTE];
    } else {
      // Senão, mantém a senha atual
      query = 'UPDATE CLIENTES SET Nome = ?, Email = ? WHERE ID_CLIENTE = ?';
      params = [Nome, Email, ID_CLIENTE];
    }

    const [result] = await dbPromise.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ message: 'Perfil atualizado com sucesso' });

  } catch (err) {
    console.error('[PUT /atualizar-perfil] erro:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: excluir ticket (APENAS TÉCNICOS/ADMINS)
----------------------------*/
app.delete('/tickets/:id', async (req, res) => {
  try {
    const ticketId = parseInt(req.params.id, 10);

    if (isNaN(ticketId) || ticketId <= 0) {
      return res.status(400).json({ error: 'ID do ticket inválido' });
    }

    // Verificar se ticket existe
    const [ticketRows] = await dbPromise.query(
      'SELECT ID_CHAMADO FROM CHAMADOS WHERE ID_CHAMADO = ?',
      [ticketId]
    );

    if (ticketRows.length === 0) {
      return res.status(404).json({ error: 'Ticket não encontrado.' });
    }

    // ✅ EXCLUIR O TICKET
    await dbPromise.query(
      'DELETE FROM CHAMADOS WHERE ID_CHAMADO = ?',
      [ticketId]
    );

    res.json({ message: 'Ticket excluído com sucesso' });

  } catch (err) {
    console.error('[DELETE /tickets/:id] erro:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: atualizar usuário (ADMIN)
----------------------------*/
app.put('/admin/usuarios/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    const { Nome, Email, Perfil_Acesso, Senha } = req.body;

    if (!Nome || !Email || !Perfil_Acesso) {
      return res.status(400).json({ error: 'Nome, Email e Perfil_Acesso são obrigatórios.' });
    }

    // Verificar se email já existe (para outro usuário)
    const [emailExists] = await dbPromise.query(
      'SELECT ID_CLIENTE FROM CLIENTES WHERE Email = ? AND ID_CLIENTE != ?',
      [Email, userId]
    );

    if (emailExists.length > 0) {
      return res.status(409).json({ error: 'Email já está em uso por outro usuário' });
    }

    let query, params;

    // Se senha foi fornecida, atualiza com senha
    if (Senha && Senha.trim() !== '') {
      const senhaHash = await bcrypt.hash(Senha, 12);
      query = 'UPDATE CLIENTES SET Nome = ?, Email = ?, Perfil_Acesso = ?, Senha_hash = ? WHERE ID_CLIENTE = ?';
      params = [Nome, Email, Perfil_Acesso, senhaHash, userId];
    } else {
      // Senão, mantém a senha atual
      query = 'UPDATE CLIENTES SET Nome = ?, Email = ?, Perfil_Acesso = ? WHERE ID_CLIENTE = ?';
      params = [Nome, Email, Perfil_Acesso, userId];
    }

    const [result] = await dbPromise.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário atualizado com sucesso' });

  } catch (err) {
    console.error('[PUT /admin/usuarios/:id] erro:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/* ---------------------------
   Rota: listar todos os usuários (ADMIN) - VERSÃO FUNCIONAL
----------------------------*/
app.get('/admin/usuarios', async (req, res) => {
  try {
    console.log('📋 Buscando lista de usuários para admin...');
    
    // ✅ VOLTAR PARA VERSÃO ORIGINAL QUE FUNCIONAVA
    const [rows] = await dbPromise.query(
      `SELECT 
         ID_CLIENTE as id, 
         Nome, 
         Email, 
         Perfil_Acesso,
         Ativo
       FROM CLIENTES 
       ORDER BY Nome`
    );
    
    console.log(`✅ Encontrados ${rows.length} usuários`);
    
    // ✅ VOLTAR PARA MAPEAMENTO ORIGINAL
    const usuarios = rows.map(user => ({
      id: user.id,
      nome: user.Nome,           // ✅ Nome (com N maiúsculo)
      email: user.Email,         // ✅ Email (com E maiúsculo)  
      perfilAcesso: user.Perfil_Acesso || 'Usuario',
      ativo: user.Ativo === 1    // ✅ Ativo (com A maiúsculo)
    }));
    
    res.json(usuarios);
    
  } catch (err) {
    console.error('[GET /admin/usuarios] erro:', err.message);
    res.status(500).json({ 
      error: 'Erro interno ao buscar usuários',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

/* ---------------------------
   Rota: listar todos os setores (ADMIN) - CORRIGIDO
----------------------------*/
app.get('/admin/setores', async (req, res) => {
  try {
    console.log('📋 Buscando lista de setores para admin...');
    
    // ✅ CORREÇÃO: SQL sem comentários e com campos consistentes
    const [rows] = await dbPromise.query(
      `SELECT 
         ID_Setor as id, 
         Nome as nome,
         Ativo as ativo
       FROM SETORES 
       ORDER BY Nome`
    );
    
    console.log(`✅ Encontrados ${rows.length} setores`);
    
    // ✅ Retornar dados consistentes
    res.json(rows);
    
  } catch (err) {
    console.error('[GET /admin/setores] erro:', err.message);
    res.status(500).json({ error: 'Erro interno ao buscar setores' });
  }
});

/* ---------------------------
   Rota: criar novo setor (ADMIN)
----------------------------*/
app.post('/admin/setores', async (req, res) => {
  try {
    const { Nome } = req.body;

    if (!Nome || Nome.trim() === '') {
      return res.status(400).json({ error: 'Nome do setor é obrigatório' });
    }

    // ✅ VERIFICAR SE SETOR JÁ EXISTE (INCLUINDO INATIVOS)
    const [exists] = await dbPromise.query(
      'SELECT ID_Setor, Ativo FROM SETORES WHERE LOWER(Nome) = LOWER(?) LIMIT 1',
      [Nome.trim()]
    );

    if (exists.length > 0) {
      const setorExistente = exists[0];
      if (setorExistente.Ativo === 0) {
        // ✅ REATIVAR SETOR INATIVO
        await dbPromise.query(
          'UPDATE SETORES SET Ativo = 1 WHERE ID_Setor = ?',
          [setorExistente.ID_Setor]
        );
        
        return res.json({
          message: 'Setor reativado com sucesso',
          id: setorExistente.ID_Setor,
          reativado: true
        });
      } else {
        return res.status(409).json({ error: 'Setor já existe' });
      }
    }

    // Criar novo setor
    const [result] = await dbPromise.query(
      'INSERT INTO SETORES (Nome) VALUES (?)',
      [Nome.trim()]
    );

    res.status(201).json({
      message: 'Setor criado com sucesso',
      id: result.insertId
    });

  } catch (err) {
    console.error('[POST /admin/setores] erro:', err.message);
    res.status(500).json({ error: 'Erro interno ao criar setor' });
  }
});
/* ---------------------------
   Rota: excluir setor (ADMIN) - SOFT DELETE
----------------------------*/
app.delete('/admin/setores/:id', async (req, res) => {
  try {
    const setId = parseInt(req.params.id, 10);

    if (isNaN(setId) || setId <= 0) {
      return res.status(400).json({ error: 'ID do setor inválido' });
    }

    // ✅ SOFT DELETE: Marcar como inativo em vez de excluir
    const [result] = await dbPromise.query(
      'UPDATE SETORES SET Ativo = 0 WHERE ID_Setor = ?',
      [setId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Setor não encontrado' });
    }

    res.json({ 
      message: 'Setor desativado com sucesso. Os tickets associados foram preservados.',
      setor_desativado: true 
    });

  } catch (err) {
    console.error('[DELETE /admin/setores/:id] erro:', err.message);
    res.status(500).json({ error: 'Erro interno ao desativar setor' });
  }
});

/* ---------------------------
   Rota: excluir usuário (ADMIN) - SOFT DELETE
----------------------------*/
app.delete('/admin/usuarios/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);

    if (isNaN(userId) || userId <= 0) {
      return res.status(400).json({ error: 'ID do usuário inválido' });
    }

    // ✅ REMOVER VERIFICAÇÃO DE TICKETS - SOFT DELETE DEVE PERMITIR SEMPRE
    // Apenas marcar como inativo
    const [result] = await dbPromise.query(
      'UPDATE CLIENTES SET Ativo = 0 WHERE ID_CLIENTE = ?',
      [userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ 
      message: 'Usuário desativado com sucesso',
      usuario_desativado: true 
    });

  } catch (err) {
    console.error('[DELETE /admin/usuarios/:id] erro:', err.message);
    res.status(500).json({ error: 'Erro interno ao desativar usuário' });
  }
});

/* ---------------------------
   Rota: reativar usuário/setor (ADMIN) - VERIFICAR
----------------------------*/
app.put('/admin/reativar/:tipo/:id', async (req, res) => {
  try {
    const { tipo, id } = req.params;
    const entityId = parseInt(id, 10);

    if (isNaN(entityId) || entityId <= 0) {
      return res.status(400).json({ error: 'ID inválido' });
    }

    let table, field;
    if (tipo === 'usuario') {
      table = 'CLIENTES';
      field = 'ID_CLIENTE';
    } else if (tipo === 'setor') {
      table = 'SETORES'; 
      field = 'ID_Setor';
    } else {
      return res.status(400).json({ error: 'Tipo inválido. Use "usuario" ou "setor"' });
    }

    // ✅ VERIFICAR se está atualizando corretamente
    const [result] = await dbPromise.query(
      `UPDATE ${table} SET Ativo = 1 WHERE ${field} = ?`,
      [entityId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `${tipo} não encontrado` });
    }

    res.json({ 
      message: `${tipo.charAt(0).toUpperCase() + tipo.slice(1)} reativado com sucesso`,
      reativado: true 
    });

  } catch (err) {
    console.error(`[PUT /admin/reativar/${tipo}] erro:`, err.message);
    res.status(500).json({ error: `Erro interno ao reativar ${tipo}` });
  }
});

/* ---------------------------
   Rota: atualizar imagens do ticket - PADRONIZADA
----------------------------*/
app.put('/tickets/:id/imagens', upload.array('Imagens', 5), async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id, 10);
        const { imagens_remover } = req.body;

        console.log('🔄 Atualizando imagens do ticket:', ticketId);
        console.log('📸 Imagens para remover:', imagens_remover);

        // Buscar ticket atual
        const [ticketRows] = await dbPromise.query(
            'SELECT Imagem FROM CHAMADOS WHERE ID_CHAMADO = ?',
            [ticketId]
        );

        if (ticketRows.length === 0) {
            return res.status(404).json({ error: 'Ticket não encontrado.' });
        }

        let imagensAtuais = [];
        const ticket = ticketRows[0];
        
        // ✅ PROCESSAR IMAGENS EXISTENTES CORRETAMENTE
        if (ticket.Imagem) {
            if (ticket.Imagem.includes(',')) {
                imagensAtuais = ticket.Imagem.split(',').map(img => img.trim());
            } else {
                imagensAtuais = [ticket.Imagem.trim()];
            }
        }

        console.log('📁 Imagens atuais no banco:', imagensAtuais);

        // ✅ REMOVER IMAGENS ESPECIFICADAS
        if (imagens_remover) {
            try {
                const imagensParaRemover = JSON.parse(imagens_remover);
                console.log('🗑️ Removendo imagens:', imagensParaRemover);
                
                imagensAtuais = imagensAtuais.filter(img => !imagensParaRemover.includes(img));
                
                // Deletar arquivos físicos do servidor
                for (let img of imagensParaRemover) {
                    const filePath = path.join(process.cwd(), 'uploads', img);
                    if (fs.existsSync(filePath)) {
                        fs.unlinkSync(filePath);
                        console.log('✅ Arquivo removido:', img);
                    } else {
                        console.log('⚠️ Arquivo não encontrado:', img);
                    }
                }
            } catch (parseError) {
                console.error('❌ Erro ao parsear imagens_remover:', parseError);
                return res.status(400).json({ error: 'Formato inválido para imagens_remover' });
            }
        }

        // ✅ ADICIONAR NOVAS IMAGENS COM PADRONIZAÇÃO
        let novasImagensPaths = [];
        if (req.files && req.files.length > 0) {
            const uploadDir = path.join(process.cwd(), 'uploads');
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }
            
            console.log('💾 Salvando novas imagens com nome padronizado...');
            for (let file of req.files) {
                // ✅ PADRONIZAR NOME DO ARQUIVO (MESMO PADRÃO DA CRIAÇÃO)
                const nomeOriginal = file.originalname;
                const extensao = path.extname(nomeOriginal) || '.jpg';
                
                const timestamp = Date.now();
                const randomStr = Math.random().toString(36).substring(2, 9);
                const fileName = `img_${timestamp}_${randomStr}${extensao}`;
                
                const filePath = path.join(uploadDir, fileName);
                fs.writeFileSync(filePath, file.buffer);
                novasImagensPaths.push(fileName);
                console.log('✅ Nova imagem salva (padronizada):', fileName, 'de:', nomeOriginal);
            }
        }

        // ✅ COMBINAR IMAGENS
        const todasImagens = [...imagensAtuais, ...novasImagensPaths];
        const imagemFinal = todasImagens.length > 0 ? todasImagens.join(',') : null;

        console.log('💾 Salvando no banco:', imagemFinal);

        // ✅ ATUALIZAR BANCO
        await dbPromise.query(
            'UPDATE CHAMADOS SET Imagem = ? WHERE ID_CHAMADO = ?',
            [imagemFinal, ticketId]
        );

        res.json({ 
            message: 'Imagens atualizadas com sucesso',
            imagens_adicionadas: novasImagensPaths.length,
            imagens_removidas: imagens_remover ? JSON.parse(imagens_remover).length : 0,
            total_imagens: todasImagens.length,
            imagens: todasImagens
        });

    } catch (err) {
        console.error('[PUT /tickets/:id/imagens] erro:', err.message);
        res.status(500).json({ error: 'Erro interno: ' + err.message });
    }
});

/* ---------------------------
   Rota: diagnóstico do servidor
----------------------------*/
app.get('/diagnostico', async (req, res) => {
    try {
        const uploadDir = path.join(process.cwd(), 'uploads');
        const existePasta = fs.existsSync(uploadDir);
        
        let arquivos = [];
        let tamanhoTotal = 0;
        
        if (existePasta) {
            arquivos = fs.readdirSync(uploadDir);
            
            // Calcular tamanho total
            arquivos.forEach(arquivo => {
                const filePath = path.join(uploadDir, arquivo);
                try {
                    const stats = fs.statSync(filePath);
                    tamanhoTotal += stats.size;
                } catch (e) {
                    console.log('Erro ao ler arquivo:', arquivo, e.message);
                }
            });
        }
        
        // Informações do sistema
        const info = {
            servidor: {
                nome: 'TaskFlow API',
                ambiente: process.env.NODE_ENV || 'development',
                porta: process.env.PORT || 3000,
                timestamp: new Date().toISOString()
            },
            uploads: {
                pasta_existe: existePasta,
                caminho: uploadDir,
                total_arquivos: arquivos.length,
                tamanho_total_bytes: tamanhoTotal,
                tamanho_total_mb: (tamanhoTotal / (1024 * 1024)).toFixed(2),
                arquivos: arquivos.slice(0, 10) // Mostrar apenas os 10 primeiros
            },
            banco_dados: {
                status: 'OK' // Poderia adicionar teste de conexão aqui
            }
        };
        
        res.json(info);
        
    } catch (err) {
        res.status(500).json({ error: 'Erro no diagnóstico: ' + err.message });
    }
});

/* ---------------------------
   Rota: verificar arquivo específico
----------------------------*/
app.get('/verificar-arquivo/:nome', async (req, res) => {
    try {
        const nomeArquivo = req.params.nome;
        const filePath = path.join(process.cwd(), 'uploads', nomeArquivo);
        const existe = fs.existsSync(filePath);
        
        let infoArquivo = {};
        if (existe) {
            const stats = fs.statSync(filePath);
            infoArquivo = {
                tamanho: stats.size,
                criado: stats.birthtime,
                modificado: stats.mtime
            };
        }
        
        res.json({
            arquivo: nomeArquivo,
            existe: existe,
            caminho: filePath,
            info: infoArquivo
        });
        
    } catch (err) {
        res.status(500).json({ error: 'Erro ao verificar arquivo: ' + err.message });
    }
});


/* ---------------------------
   Inicializa o servidor
----------------------------*/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 API rodando na porta ${PORT}`));